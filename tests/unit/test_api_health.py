"""HTTP tests for liveness, readiness, and Prometheus metrics."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.constants.api import HEALTH_LIVE_PATH, HEALTH_READY_PATH, METRICS_PATH
from app.constants.metrics import (
    EVENTS_TOTAL,
    FORBIDDEN_LABELS,
    KAFKA_CONSUMER_LAG,
    OUTBOX_PENDING,
    PREDICTIONS_TOTAL,
    PROCESSING_SECONDS,
    QOE_FLUSH_TOTAL,
    QVAC_AVAILABLE,
    QVAC_SECONDS,
    WAZUH_DELIVERY_TOTAL,
)
from app.core.config import Settings
from app.domain.enums import DependencyStatus
from app.main import SentinelApp

WEBHOOK_TOKEN = "unit-test-webhook-token"


def _client() -> TestClient:
    return TestClient(SentinelApp.create(Settings(webhook_token=WEBHOOK_TOKEN)))


def test_health_live_returns_ok() -> None:
    with _client() as client:
        response = client.get(HEALTH_LIVE_PATH)
    assert response.status_code == 200
    assert response.json()["status"] == "live"


def test_health_ready_when_qvac_and_kafka_are_stubbed() -> None:
    with _client() as client:
        response = client.get(HEALTH_READY_PATH)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    by_name = {item["name"]: item for item in body["dependencies"]}
    assert by_name["config"]["status"] == DependencyStatus.UP.value
    assert by_name["qvac"]["status"] == DependencyStatus.DEGRADED.value
    assert by_name["kafka"]["status"] == DependencyStatus.DEGRADED.value
    assert by_name["outbox"]["status"] == DependencyStatus.DEGRADED.value


def test_metrics_exposes_spec_names_without_identity_labels() -> None:
    with _client() as client:
        response = client.get(METRICS_PATH)
    assert response.status_code == 200
    text = response.text
    for name in (
        EVENTS_TOTAL,
        PREDICTIONS_TOTAL,
        PROCESSING_SECONDS,
        QVAC_SECONDS,
        QVAC_AVAILABLE,
        KAFKA_CONSUMER_LAG,
        OUTBOX_PENDING,
        WAZUH_DELIVERY_TOTAL,
        QOE_FLUSH_TOTAL,
    ):
        assert name in text
    for label in FORBIDDEN_LABELS:
        assert f"{label}=" not in text
