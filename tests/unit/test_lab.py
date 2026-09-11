"""Local QVAC lab: synthetic catalog and fidelity evaluation."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.constants.api import (
    LAB_CATALOG_PATH,
    LAB_EVALUATE_PATH,
    LAB_PATH,
    WEBHOOK_TOKEN_HEADER,
)
from app.core.config import Settings
from app.main import SentinelApp
from app.services.lab_fidelity import LabBatchSampler, LabFidelityService
from simulator.main import plan
from simulator.profiles import DEFAULT_ZONE, SITES
from simulator.scenarios import get_scenario

WEBHOOK_TOKEN = "unit-test-webhook-token"


def _client() -> TestClient:
    return TestClient(SentinelApp.create(Settings(webhook_token=WEBHOOK_TOKEN)))


def test_lab_page_is_served() -> None:
    with _client() as client:
        response = client.get(LAB_PATH)
    assert response.status_code == 200
    assert "Lab QVAC" in response.text
    assert LAB_EVALUATE_PATH in response.text


def test_catalog_lists_simulator_scenarios() -> None:
    with _client() as client:
        response = client.get(LAB_CATALOG_PATH)
    assert response.status_code == 200
    names = {item["name"] for item in response.json()}
    assert "mixed_demo" in names
    assert "dga_burst" in names
    assert "typosquatting" in names


def test_evaluate_requires_token() -> None:
    with _client() as client:
        response = client.post(
            LAB_EVALUATE_PATH,
            json={"scenario": "dga_burst", "limit": 4, "duration_s": 5, "seed": 42},
        )
    assert response.status_code == 401


def test_evaluate_rejects_unknown_scenario() -> None:
    with _client() as client:
        response = client.post(
            LAB_EVALUATE_PATH,
            headers={WEBHOOK_TOKEN_HEADER: WEBHOOK_TOKEN},
            json={"scenario": "no-existe", "limit": 4, "duration_s": 5, "seed": 42},
        )
    assert response.status_code == 422


def test_evaluate_returns_fidelity_rows() -> None:
    with _client() as client:
        response = client.post(
            LAB_EVALUATE_PATH,
            headers={WEBHOOK_TOKEN_HEADER: WEBHOOK_TOKEN},
            json={"scenario": "dga_burst", "limit": 6, "duration_s": 5, "seed": 42},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["scenario"] == "dga_burst"
    assert body["seed"] == 42
    assert body["sampled"] == len(body["rows"])
    assert body["sampled"] >= 1
    assert 0.0 <= body["summary"]["accuracy"] <= 1.0
    row = body["rows"][0]
    assert row["expected_threat"]
    assert row["predicted_threat"]
    assert "qvac_used" in row
    assert "." in row["qname"]


def test_sampler_covers_multiple_labels() -> None:
    spec = get_scenario("dga_burst")
    planned = plan(
        "dga_burst",
        sites=[SITES[0]],
        zones=[DEFAULT_ZONE],
        rate_per_s=spec.default_rate_per_s,
        duration_s=8.0,
        seed=42,
    )
    sampled = LabBatchSampler.take(planned, 8)
    labels = {item.query.ground_truth.threat_type for item in sampled}
    assert len(sampled) >= 2
    assert len(sampled) <= 8
    assert "dga" in labels
    assert "none" in labels


def test_catalog_service_matches_simulator() -> None:
    names = [item.name for item in LabFidelityService().catalog()]
    assert "normal" in names
    assert "beaconing" in names
    assert "mixed_demo" in names
