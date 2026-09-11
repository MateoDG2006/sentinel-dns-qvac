"""Shared PredictionService for webhook and Kafka. No second detection path."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from app.core.config import Settings
from app.domain.enums import (
    DependencyStatus,
    EventSource,
    PredictionMode,
    Severity,
    ThreatType,
    WazuhEventType,
)
from app.domain.errors import KafkaBackpressureError, OutboxFullError, QvacTimeoutError
from app.domain.schemas import (
    DependencyHealth,
    HeuristicVerdict,
    NormalizedDnsEvent,
    OutboxRecord,
    QvacCandidate,
    QvacVerdict,
)
from app.services.prediction import InternalQueue, PredictionService, VolatileOutbox
from app.services.qvac_enrichment import QvacEnrichmentService
from app.utils.time import UtcDateTime


def _event(**overrides: Any) -> NormalizedDnsEvent:
    payload: dict[str, Any] = {
        "event_id": uuid4(),
        "event_ts": datetime.now(UTC),
        "observed_at": datetime.now(UTC),
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
    return NormalizedDnsEvent.model_validate(payload)


class FakeQvacPort:
    def __init__(
        self,
        *,
        verdict: QvacVerdict | None = None,
        error: Exception | None = None,
    ) -> None:
        self.calls = 0
        self._verdict = verdict
        self._error = error

    async def start(self) -> None:
        return None

    async def enrich(self, candidate: QvacCandidate) -> QvacVerdict:
        self.calls += 1
        if self._error is not None:
            raise self._error
        assert self._verdict is not None
        return self._verdict

    async def health(self) -> DependencyHealth:
        return DependencyHealth(
            name="qvac",
            status=DependencyStatus.UP,
            detail=None,
            checked_at=UtcDateTime.ensure(datetime.now(UTC)),
        )

    async def close(self) -> None:
        return None


class FakeDetector:
    def __init__(self, verdict: HeuristicVerdict) -> None:
        self._verdict = verdict

    def evaluate(self, event: NormalizedDnsEvent, features: object) -> HeuristicVerdict:
        _ = (event, features)
        return self._verdict


class FakeQoe:
    def __init__(self) -> None:
        self.events: list[NormalizedDnsEvent] = []

    def observe(self, event: NormalizedDnsEvent) -> None:
        self.events.append(event)


class FullOutbox:
    async def enqueue(self, record: OutboxRecord) -> bool:
        _ = record
        raise OutboxFullError()

    async def claim_batch(self, limit: int) -> list[OutboxRecord]:
        _ = limit
        return []

    async def mark_delivered(self, ids: list[UUID]) -> None:
        _ = ids

    async def reschedule(self, ids: list[UUID], retry_at: datetime, reason: str) -> None:
        _ = (ids, retry_at, reason)

    async def mark_dead(self, ids: list[UUID], reason: str) -> None:
        _ = (ids, reason)


def _ambiguous_dga() -> HeuristicVerdict:
    return HeuristicVerdict(
        threat_type=ThreatType.DGA,
        score=0.70,
        severity=Severity.HIGH,
        reasons=["high_entropy"],
    )


async def test_webhook_and_kafka_share_idempotent_prediction_id() -> None:
    event = _event()
    service = PredictionService(Settings())
    webhook = await service.process_batch([event], EventSource.WEBHOOK)
    kafka = await service.process_batch([event], EventSource.KAFKA)
    assert webhook[0].prediction.prediction_id == kafka[0].prediction.prediction_id
    assert webhook[0].prediction.event_id == event.event_id
    assert kafka[0].prediction is webhook[0].prediction


async def test_benign_event_is_heuristic_fallback_without_outbox_threat() -> None:
    outbox = VolatileOutbox()
    qoe = FakeQoe()
    service = PredictionService(Settings(), outbox=outbox, qoe=qoe)
    results = await service.process_batch([_event()], EventSource.KAFKA)
    assert results[0].mode is PredictionMode.HEURISTIC_FALLBACK
    assert results[0].prediction.threat_type is ThreatType.NONE
    assert outbox.payloads() == []
    assert len(qoe.events) == 1


async def test_qvac_timeout_falls_back_and_enqueues_operational_alert() -> None:
    port = FakeQvacPort(error=QvacTimeoutError())
    settings = Settings()
    outbox = VolatileOutbox()
    service = PredictionService(
        settings,
        detector=FakeDetector(_ambiguous_dga()),
        enrichment=QvacEnrichmentService(port, settings=settings),
        outbox=outbox,
    )
    first = _event()
    second = _event()
    results = await service.process_batch([first, second], EventSource.KAFKA)
    assert port.calls == 2
    assert all(item.mode is PredictionMode.HEURISTIC_FALLBACK for item in results)
    assert all(item.prediction.degraded is True for item in results)
    types = {record.record_type for record in outbox.payloads()}
    assert WazuhEventType.DNS_THREAT in types
    assert WazuhEventType.SENTINEL_OPERATIONAL in types
    operational = [
        record
        for record in outbox.payloads()
        if record.record_type is WazuhEventType.SENTINEL_OPERATIONAL
    ]
    assert len(operational) == 1


async def test_high_confidence_skips_qvac_hot_path() -> None:
    port = FakeQvacPort(error=QvacTimeoutError())
    settings = Settings()
    verdict = HeuristicVerdict(
        threat_type=ThreatType.DGA,
        score=0.95,
        severity=Severity.CRITICAL,
        reasons=["high_entropy"],
    )
    service = PredictionService(
        settings,
        detector=FakeDetector(verdict),
        enrichment=QvacEnrichmentService(port, settings=settings),
    )
    results = await service.process_batch([_event()], EventSource.WEBHOOK)
    assert port.calls == 0
    assert results[0].prediction.threat_type is ThreatType.DGA
    assert results[0].prediction.degraded is False


async def test_full_queue_raises_backpressure() -> None:
    settings = Settings(internal_queue_max_events=1)
    service = PredictionService(
        settings,
        queue=InternalQueue(max_events=1, depth=1),
    )
    with pytest.raises(KafkaBackpressureError):
        await service.process_batch([_event()], EventSource.KAFKA)


async def test_full_outbox_becomes_backpressure() -> None:
    service = PredictionService(
        Settings(),
        detector=FakeDetector(_ambiguous_dga()),
        outbox=FullOutbox(),
    )
    with pytest.raises(KafkaBackpressureError):
        await service.process_batch([_event()], EventSource.WEBHOOK)
