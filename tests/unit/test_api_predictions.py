"""HTTP tests for webhook auth, batch limits, and backpressure."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from fastapi.testclient import TestClient

from app.constants.api import (
    PREDICTION_BATCH_MAX,
    PREDICTIONS_PATH,
    WEBHOOK_RETRY_AFTER_SECONDS,
    WEBHOOK_TOKEN_HEADER,
)
from app.core.config import Settings
from app.domain.enums import PredictionMode
from app.main import SentinelApp
from app.services.prediction import InternalQueue, PredictionService

WEBHOOK_TOKEN = "unit-test-webhook-token"


def _event_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_id": str(uuid4()),
        "event_ts": datetime(2026, 9, 10, 12, 0, tzinfo=UTC).isoformat(),
        "observed_at": datetime(2026, 9, 10, 12, 0, tzinfo=UTC).isoformat(),
        "site_id": "pop-1",
        "zone_id": "zone-a",
        "resolver_id": "resolver-1",
        "client_hash": "client-hash-1",
        "qname": "www.example.com",
        "qtype": "A",
        "rcode": "NOERROR",
        "latency_ms": 25.0,
        "response_bytes": 128,
        "timed_out": False,
        "synthetic": True,
    }
    payload.update(overrides)
    return payload


def _client(settings: Settings | None = None) -> TestClient:
    resolved = settings or Settings(webhook_token=WEBHOOK_TOKEN)
    return TestClient(SentinelApp.create(resolved))


def _auth_headers(token: str = WEBHOOK_TOKEN) -> dict[str, str]:
    return {WEBHOOK_TOKEN_HEADER: token}


def test_missing_token_returns_401() -> None:
    with _client() as client:
        response = client.post(PREDICTIONS_PATH, json={"events": [_event_payload()]})
    assert response.status_code == 401
    assert WEBHOOK_TOKEN.lower() not in response.text.lower()


def test_invalid_token_returns_401() -> None:
    with _client() as client:
        response = client.post(
            PREDICTIONS_PATH,
            json={"events": [_event_payload()]},
            headers=_auth_headers("wrong-token"),
        )
    assert response.status_code == 401
    assert "wrong-token" not in response.text


def test_single_event_batch_returns_202() -> None:
    correlation_id = str(uuid4())
    with _client() as client:
        response = client.post(
            PREDICTIONS_PATH,
            json={"events": [_event_payload()], "correlation_id": correlation_id},
            headers=_auth_headers(),
        )
    assert response.status_code == 202
    body = response.json()
    assert body["correlation_id"] == correlation_id
    assert body["accepted"] == 1
    assert body["rejected"] == 0
    assert len(body["result_ids"]) == 1
    assert body["mode"] == PredictionMode.HEURISTIC_FALLBACK.value


def test_batch_of_one_hundred_returns_202() -> None:
    events = [_event_payload() for _ in range(PREDICTION_BATCH_MAX)]
    with _client() as client:
        response = client.post(
            PREDICTIONS_PATH,
            json={"events": events},
            headers=_auth_headers(),
        )
    assert response.status_code == 202
    body = response.json()
    assert body["accepted"] == PREDICTION_BATCH_MAX
    assert body["rejected"] == 0
    assert len(body["result_ids"]) == PREDICTION_BATCH_MAX


def test_non_synthetic_event_returns_422() -> None:
    with _client() as client:
        response = client.post(
            PREDICTIONS_PATH,
            json={"events": [_event_payload(synthetic=False)]},
            headers=_auth_headers(),
        )
    assert response.status_code == 422


def test_invalid_qname_returns_422() -> None:
    with _client() as client:
        response = client.post(
            PREDICTIONS_PATH,
            json={"events": [_event_payload(qname="example..com")]},
            headers=_auth_headers(),
        )
    assert response.status_code == 422


def test_empty_batch_returns_422() -> None:
    with _client() as client:
        response = client.post(
            PREDICTIONS_PATH,
            json={"events": []},
            headers=_auth_headers(),
        )
    assert response.status_code == 422


def test_batch_over_limit_returns_422() -> None:
    events = [_event_payload() for _ in range(PREDICTION_BATCH_MAX + 1)]
    with _client() as client:
        response = client.post(
            PREDICTIONS_PATH,
            json={"events": events},
            headers=_auth_headers(),
        )
    assert response.status_code == 422


def test_full_internal_queue_returns_429_with_retry_after() -> None:
    settings = Settings(webhook_token=WEBHOOK_TOKEN, internal_queue_max_events=10)
    application = SentinelApp.create(settings)
    application.state.prediction_service = PredictionService(
        settings=settings,
        queue=InternalQueue(max_events=settings.internal_queue_max_events, depth=10),
    )
    with TestClient(application) as client:
        response = client.post(
            PREDICTIONS_PATH,
            json={"events": [_event_payload()]},
            headers=_auth_headers(),
        )
    assert response.status_code == 429
    assert response.headers["retry-after"] == str(WEBHOOK_RETRY_AFTER_SECONDS)
