"""Composition-root wiring: durable outbox and QoE sink share PredictionService."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from fastapi.testclient import TestClient

from app.constants.api import PREDICTIONS_PATH, WEBHOOK_TOKEN_HEADER
from app.core.config import Settings
from app.infrastructure.persistence.sqlite import SqliteOutbox
from app.main import SentinelApp
from app.services.qoe import DnsQoeSink

WEBHOOK_TOKEN = "unit-test-webhook-token"


def _event_payload() -> dict[str, object]:
    return {
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


def test_lifespan_wires_sqlite_outbox_and_qoe_sink() -> None:
    application = SentinelApp.create(Settings(webhook_token=WEBHOOK_TOKEN))
    with TestClient(application) as client:
        assert isinstance(application.state.outbox, SqliteOutbox)
        assert isinstance(application.state.qoe, DnsQoeSink)
        response = client.post(
            PREDICTIONS_PATH,
            json={"events": [_event_payload()]},
            headers={WEBHOOK_TOKEN_HEADER: WEBHOOK_TOKEN},
        )
        assert response.status_code == 202
        assert application.state.qoe.aggregator.pending_windows == 1
