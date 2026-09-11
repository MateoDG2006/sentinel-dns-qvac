"""Composition-root wiring: durable outbox, QoE sink, and flush retries."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from fastapi.testclient import TestClient

from app.constants.api import PREDICTIONS_PATH, WEBHOOK_TOKEN_HEADER
from app.core.config import Settings
from app.core.lifecycle import QoeFlushWorker
from app.infrastructure.clickhouse.client import DependencyState
from app.infrastructure.persistence.sqlite import SqliteOutbox
from app.main import SentinelApp
from app.services.qoe import DnsQoeSink, QoeWindowResult

WEBHOOK_TOKEN = "unit-test-webhook-token"
_NOW = datetime(2026, 9, 10, 12, 2, tzinfo=UTC)


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


def _window() -> QoeWindowResult:
    return QoeWindowResult(
        window_start=datetime(2026, 9, 10, 12, 0, tzinfo=UTC),
        site_id="pop-1",
        zone_id="zone-a",
        sample_count=20,
        latency_p50_ms=10.0,
        latency_p95_ms=20.0,
        latency_p99_ms=30.0,
        nxdomain_rate=0.0,
        servfail_rate=0.0,
        timeout_rate=0.0,
        saturation_index=0.0,
        latency_score=1.0,
        resolution_score=1.0,
        saturation_score=1.0,
        qoe_score=1.0,
        status="good",
        primary_cause="latencia_alta",
        calculation_version="1.0",
        updated_at=_NOW,
    )


class _FakeAggregator:
    def __init__(self, batches: list[list[QoeWindowResult]]) -> None:
        self._batches = batches

    def collect_due_windows(self, now: datetime) -> list[QoeWindowResult]:
        _ = now
        if not self._batches:
            return []
        return self._batches.pop(0)


class _FakeRepository:
    def __init__(self, *, healthy: bool = True, fail_upsert: int = 0) -> None:
        self.healthy = healthy
        self.fail_upsert = fail_upsert
        self.upserts: list[list[QoeWindowResult]] = []

    async def health(self) -> DependencyState:
        return DependencyState("clickhouse", self.healthy, None, _NOW)

    async def upsert_windows(self, windows: list[QoeWindowResult]) -> None:
        if self.fail_upsert > 0:
            self.fail_upsert -= 1
            raise RuntimeError("clickhouse_insert_failed")
        self.upserts.append(list(windows))


class _FakeMetrics:
    def __init__(self) -> None:
        self.flushes: list[tuple[str, int]] = []

    def increment_qoe_flush(self, *, status: str, amount: int = 1) -> None:
        self.flushes.append((status, amount))


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


async def test_qoe_flush_retries_windows_if_upsert_fails() -> None:
    window = _window()
    aggregator = _FakeAggregator([[window]])
    repository = _FakeRepository(fail_upsert=1)
    metrics = _FakeMetrics()
    worker = QoeFlushWorker(aggregator, repository, metrics)  # type: ignore[arg-type]

    await worker.tick(_NOW)
    assert worker.pending_count == 1
    assert repository.upserts == []
    assert metrics.flushes[-1] == ("error", 1)

    await worker.tick(_NOW)
    assert worker.pending_count == 0
    assert len(repository.upserts) == 1
    assert repository.upserts[0] == [window]
    assert metrics.flushes[-1] == ("ok", 1)


async def test_qoe_flush_does_not_collect_when_clickhouse_is_down() -> None:
    window = _window()
    aggregator = _FakeAggregator([[window]])
    repository = _FakeRepository(healthy=False)
    worker = QoeFlushWorker(aggregator, repository, _FakeMetrics())  # type: ignore[arg-type]

    await worker.tick(_NOW)
    assert worker.pending_count == 0
    assert aggregator._batches == [[window]]
