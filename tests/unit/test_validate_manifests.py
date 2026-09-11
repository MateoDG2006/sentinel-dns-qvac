"""Static policy for Kubernetes manifests (C5). Rendering tests skip without kubectl."""

from __future__ import annotations

import shutil
from pathlib import Path
from textwrap import dedent

import pytest
import yaml
from scripts.validate_manifests import ManifestPolicy, ManifestValidator

from app.constants.kafka import TOPIC_DLQ, TOPIC_GROUNDTRUTH, TOPIC_NORMALIZED
from app.constants.kubernetes import OVERLAY_LOCAL
from app.constants.network import LOCAL_SERVICE_HOSTS

_CLUSTER_SERVICES = LOCAL_SERVICE_HOSTS - {"localhost", "host.docker.internal"}
_REPO = Path(__file__).resolve().parents[2]
_OVERLAY = _REPO / OVERLAY_LOCAL
_K8S_FILE_COPIES = (
    (_REPO / "config" / "features.yaml", _REPO / "deploy/kubernetes/base/files/features.yaml"),
    (_REPO / "config" / "brands.yaml", _REPO / "deploy/kubernetes/base/files/brands.yaml"),
    (
        _REPO / "config" / "qoe_thresholds.yaml",
        _REPO / "deploy/kubernetes/base/files/qoe_thresholds.yaml",
    ),
    (
        _REPO / "deploy/clickhouse/init/001_qoe.sql",
        _REPO / "deploy/kubernetes/base/files/001_qoe.sql",
    ),
    (
        _REPO / "deploy/grafana/provisioning/datasources/clickhouse.yaml",
        _REPO / "deploy/kubernetes/base/files/clickhouse.yaml",
    ),
    (
        _REPO / "deploy/grafana/provisioning/dashboards/provider.yaml",
        _REPO / "deploy/kubernetes/base/files/provider.yaml",
    ),
    (
        _REPO / "deploy/grafana/provisioning/dashboards/sentinel-dns.json",
        _REPO / "deploy/kubernetes/base/files/sentinel-dns.json",
    ),
    (
        _REPO / "deploy/prometheus/prometheus.yml",
        _REPO / "deploy/kubernetes/base/files/prometheus.yml",
    ),
    (
        _REPO / "deploy/wazuh/rules/sentinel_dns_rules.xml",
        _REPO / "deploy/kubernetes/base/files/sentinel_dns_rules.xml",
    ),
)


def test_kustomize_config_copies_match_compose_sources() -> None:
    for source, copy in _K8S_FILE_COPIES:
        assert copy.read_bytes() == source.read_bytes(), f"{copy} drifted from {source}"


def _docs(raw: str) -> list[dict[str, object]]:
    return [doc for doc in yaml.safe_load_all(dedent(raw)) if doc]


def test_policy_rejects_loadbalancer() -> None:
    findings = ManifestPolicy().findings(
        _docs(
            """
            apiVersion: v1
            kind: Service
            metadata:
              name: kafka
            spec:
              type: LoadBalancer
              ports:
                - port: 9092
            """
        )
    )
    assert any("LoadBalancer" in item for item in findings)


def test_policy_rejects_latest_and_untagged_images() -> None:
    findings = ManifestPolicy().findings(
        _docs(
            """
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: sentinel-api
            spec:
              template:
                spec:
                  containers:
                    - name: api
                      image: sentinel-dns/api:latest
                    - name: helper
                      image: busybox
            """
        )
    )
    assert any("latest" in item for item in findings)
    assert any("busybox" in item for item in findings)


def test_policy_accepts_digest_and_pinned_tag() -> None:
    digest = "a" * 64
    findings = ManifestPolicy().findings(
        [
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "prometheus"},
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {"name": "prometheus", "image": "prom/prometheus:v2.55.1"},
                                {
                                    "name": "pinned",
                                    "image": f"sentinel-dns/api@sha256:{digest}",
                                },
                            ]
                        }
                    }
                },
            }
        ]
    )
    assert findings == []


def test_policy_rejects_privileged_and_literal_secrets() -> None:
    findings = ManifestPolicy().findings(
        _docs(
            """
            apiVersion: v1
            kind: Pod
            metadata:
              name: bad
            spec:
              containers:
                - name: root
                  image: apache/kafka:3.8.1
                  securityContext:
                    privileged: true
            ---
            apiVersion: v1
            kind: Secret
            metadata:
              name: leaked
            stringData:
              password: hunter2
            """
        )
    )
    assert any("privileged" in item for item in findings)
    assert any("stringData" in item for item in findings)


def test_api_server_unreachable_detects_discovery_errors() -> None:
    assert ManifestValidator.api_server_unreachable(
        'couldn\'t get current server API group list: Get "http://localhost:8080/api"'
    )
    assert not ManifestValidator.api_server_unreachable("service/kafka created (dry run)")


def test_policy_allows_optional_secret_refs_without_literal_values() -> None:
    findings = ManifestPolicy().findings(
        _docs(
            """
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: sentinel-api
            spec:
              template:
                spec:
                  containers:
                    - name: api
                      image: sentinel-dns/api:0.1.0
                      env:
                        - name: SENTINEL_WEBHOOK_TOKEN
                          valueFrom:
                            secretKeyRef:
                              name: sentinel-credentials
                              key: webhook_token
                              optional: true
            """
        )
    )
    assert findings == []


@pytest.mark.skipif(
    shutil.which("kubectl") is None and shutil.which("kustomize") is None,
    reason="kustomize renderer missing",
)
def test_local_overlay_renders_frozen_services_and_passes_policy() -> None:
    rendered = ManifestValidator().render(_OVERLAY)
    documents = _docs(rendered)
    assert ManifestPolicy().findings(documents) == []
    names = {
        str((doc.get("metadata") or {}).get("name"))
        for doc in documents
        if doc.get("kind") == "Service"
    }
    assert _CLUSTER_SERVICES <= names
    kinds = {doc.get("kind") for doc in documents}
    assert "NetworkPolicy" in kinds
    assert "Namespace" in kinds
    assert TOPIC_NORMALIZED in rendered
    assert TOPIC_DLQ in rendered
    assert TOPIC_GROUNDTRUTH in rendered
    assert "LoadBalancer" not in rendered
    assert ":latest" not in rendered
    assert "privileged: true" not in rendered
    assert "stringData:" not in rendered
    rules = (_REPO / "deploy/wazuh/rules/sentinel_dns_rules.xml").read_text(encoding="utf-8")
    assert "<if_sid>86600</if_sid>" in rules
    assert "<decoded_as>sentinel_dns</decoded_as>" not in rules
