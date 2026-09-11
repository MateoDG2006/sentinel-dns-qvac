"""Shared prediction pipeline for the Kafka consumer and the webhook."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import UTC, datetime
from statistics import mean, pstdev
from typing import Protocol
from uuid import UUID, uuid5

from app.constants.prediction import PREDICTION_ID_NAMESPACE
from app.core.config import Settings
from app.domain.enums import (
    DetectorRuntime,
    EventSource,
    OutboxStatus,
    PredictionMode,
    ThreatType,
    WazuhEventType,
)
from app.domain.errors import KafkaBackpressureError, OutboxFullError
from app.domain.ports import OutboxPort
from app.domain.schemas import (
    DnsFeatures,
    HeuristicVerdict,
    NormalizedDnsEvent,
    OutboxRecord,
    PredictionResult,
    QvacCandidate,
    TemporalContext,
    ThreatPrediction,
    WazuhDetectorFields,
    WazuhDnsFields,
    WazuhThreatEvent,
    WazuhThreatFields,
)
from app.services.feature_extraction import FeatureExtractor
from app.services.heuristics import HeuristicThreatDetector
from app.services.qvac_enrichment import QvacEnrichmentResult, QvacEnrichmentService
from app.utils.time import UtcDateTime


class QoeSink(Protocol):
    """C2's QoeAggregator.observe. A5 only requires observe-after-predict via this port."""

    def observe(self, event: NormalizedDnsEvent) -> None: ...


class NullQoeSink:
    def observe(self, event: NormalizedDnsEvent) -> None:
        _ = event


class InternalQueue:
    """In-memory depth used for webhook/consumer backpressure."""

    def __init__(self, *, max_events: int, depth: int = 0) -> None:
        self._max_events = max_events
        self._depth = depth

    @property
    def depth(self) -> int:
        return self._depth

    @property
    def max_events(self) -> int:
        return self._max_events

    def is_over_capacity(self) -> bool:
        return self._depth >= self._max_events

    def acquire(self, amount: int = 1) -> None:
        if amount < 0:
            raise ValueError("queue acquire amount must be >= 0")
        if self._depth + amount > self._max_events:
            raise KafkaBackpressureError()
        self._depth += amount

    def release(self, amount: int = 1) -> None:
        self._depth = max(0, self._depth - max(0, amount))

    def override_depth(self, depth: int) -> None:
        self._depth = depth


class QueryWindow:
    """Per-client timestamps used to fill TemporalContext."""

    def __init__(self, *, window_seconds: int) -> None:
        self._window_seconds = window_seconds
        self._stamps: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
        self._client_qnames: dict[str, dict[str, datetime]] = defaultdict(dict)

    def observe(self, event: NormalizedDnsEvent) -> TemporalContext:
        now = UtcDateTime.ensure(event.event_ts)
        cutoff = now.timestamp() - float(self._window_seconds)
        key = (event.client_hash, event.qname)
        stamps = self._stamps[key]
        stamps.append(now)
        while stamps and stamps[0].timestamp() < cutoff:
            stamps.popleft()
        seen = self._client_qnames[event.client_hash]
        seen[event.qname] = now
        expired = [name for name, stamp in seen.items() if stamp.timestamp() < cutoff]
        for name in expired:
            del seen[name]
        intervals = [
            (stamps[index] - stamps[index - 1]).total_seconds() * 1000.0
            for index in range(1, len(stamps))
        ]
        if not intervals:
            interval_mean: float | None = None
            jitter: float | None = None
        elif len(intervals) == 1:
            interval_mean = mean(intervals)
            jitter = 0.0
        else:
            interval_mean = mean(intervals)
            jitter = pstdev(intervals)
        return TemporalContext(
            query_count_1m=len(stamps),
            distinct_subdomains_1m=len(seen),
            interval_mean_ms=interval_mean,
            interval_jitter_ms=jitter,
        )


class VolatileOutbox:
    """Process-local OutboxPort until B1's durable SQLite adapter is wired."""

    def __init__(self) -> None:
        self._records: dict[tuple[UUID, WazuhEventType], OutboxRecord] = {}

    async def enqueue(self, record: OutboxRecord) -> bool:
        key = (record.event_id, record.record_type)
        if key in self._records:
            return False
        self._records[key] = record
        return True

    async def claim_batch(self, limit: int) -> list[OutboxRecord]:
        pending = [item for item in self._records.values() if item.status is OutboxStatus.PENDING]
        return pending[:limit]

    async def mark_delivered(self, ids: list[UUID]) -> None:
        delivered = set(ids)
        updated: dict[tuple[UUID, WazuhEventType], OutboxRecord] = {}
        for key, record in self._records.items():
            if record.id in delivered:
                updated[key] = record.model_copy(update={"status": OutboxStatus.DELIVERED})
            else:
                updated[key] = record
        self._records = updated

    async def reschedule(self, ids: list[UUID], retry_at: datetime, reason: str) -> None:
        _ = (ids, retry_at, reason)

    async def mark_dead(self, ids: list[UUID], reason: str) -> None:
        _ = (ids, reason)

    def payloads(self) -> list[OutboxRecord]:
        return list(self._records.values())


class PredictionService:
    """Single pipeline for Kafka and POST /api/v1/predictions."""

    def __init__(
        self,
        settings: Settings,
        *,
        extractor: FeatureExtractor | None = None,
        detector: HeuristicThreatDetector | None = None,
        enrichment: QvacEnrichmentService | None = None,
        outbox: OutboxPort | None = None,
        qoe: QoeSink | None = None,
        queue: InternalQueue | None = None,
    ) -> None:
        self._settings = settings
        self._extractor = extractor or FeatureExtractor(settings=settings)
        self._detector = detector or HeuristicThreatDetector(settings=settings)
        self._enrichment = enrichment
        self._outbox: OutboxPort = outbox or VolatileOutbox()
        self._qoe = qoe or NullQoeSink()
        self._queue = queue or InternalQueue(max_events=settings.internal_queue_max_events)
        self._history = QueryWindow(window_seconds=settings.qoe_window_seconds)
        self._results_by_event: dict[UUID, PredictionResult] = {}
        self._qvac_degraded_alerted = False

    @property
    def queue(self) -> InternalQueue:
        return self._queue

    @property
    def outbox(self) -> OutboxPort:
        return self._outbox

    async def process_batch(
        self,
        events: list[NormalizedDnsEvent],
        source: EventSource,
    ) -> list[PredictionResult]:
        if self._queue.is_over_capacity() or len(events) > self._queue.max_events:
            raise KafkaBackpressureError()
        self._queue.acquire(len(events))
        results: list[PredictionResult] = []
        try:
            for event in events:
                cached = self._results_by_event.get(event.event_id)
                if cached is not None:
                    results.append(cached)
                    continue
                result = await self._process_one(event, source)
                self._results_by_event[event.event_id] = result
                results.append(result)
        finally:
            self._queue.release(len(events))
        return results

    async def _process_one(
        self,
        event: NormalizedDnsEvent,
        source: EventSource,
    ) -> PredictionResult:
        history = self._history.observe(event)
        features = self._extractor.extract(event, history)
        heuristic = self._detector.evaluate(event, features)
        enrichment = await self._enrich(event, features, heuristic)
        prediction, mode = self._assemble(event, heuristic, enrichment)
        result = PredictionResult(prediction=prediction, source=source, mode=mode)
        self._qoe.observe(event)
        if prediction.threat_type is not ThreatType.NONE:
            await self._enqueue_threat(event, prediction, mode)
        if enrichment.degraded:
            await self._enqueue_qvac_degraded(event, prediction)
        return result

    async def _enrich(
        self,
        event: NormalizedDnsEvent,
        features: DnsFeatures,
        heuristic: HeuristicVerdict,
    ) -> QvacEnrichmentResult:
        if self._enrichment is None:
            return QvacEnrichmentResult(heuristic=heuristic, qvac=None, degraded=False)
        candidate = QvacCandidate(
            event_id=event.event_id,
            qname=event.qname,
            qtype=event.qtype,
            rcode=event.rcode,
            features=features,
            heuristic_score=heuristic.score,
            heuristic_threat_type=heuristic.threat_type,
            heuristic_reasons=heuristic.reasons,
        )
        return await self._enrichment.enrich(candidate, heuristic)

    def _assemble(
        self,
        event: NormalizedDnsEvent,
        heuristic: HeuristicVerdict,
        enrichment: QvacEnrichmentResult,
    ) -> tuple[ThreatPrediction, PredictionMode]:
        qvac = enrichment.qvac
        model_id: str | None
        if qvac is not None and qvac.score >= heuristic.score:
            threat_type = qvac.threat_type
            confidence = qvac.score
            reasons = list(qvac.reasons) or list(heuristic.reasons)
            mode = PredictionMode.HYBRID
            model_id = qvac.model_id
        else:
            threat_type = heuristic.threat_type
            confidence = heuristic.score
            reasons = list(heuristic.reasons)
            mode = (
                PredictionMode.HEURISTIC_FALLBACK
                if enrichment.degraded or qvac is None
                else PredictionMode.HYBRID
            )
            model_id = qvac.model_id if qvac is not None else None
        if (
            threat_type is not ThreatType.NONE
            and confidence < self._settings.heuristic_qvac_min_score
            and qvac is None
        ):
            threat_type = ThreatType.NONE
        return (
            ThreatPrediction(
                prediction_id=uuid5(
                    PREDICTION_ID_NAMESPACE,
                    f"{event.event_id}:{self._settings.detector_version}",
                ),
                event_id=event.event_id,
                created_at=datetime.now(UTC),
                detector_version=self._settings.detector_version,
                model_id=model_id,
                threat_type=threat_type,
                confidence=confidence,
                severity=heuristic.severity,
                reasons=reasons,
                heuristic_score=heuristic.score,
                qvac_score=qvac.score if qvac is not None else None,
                degraded=enrichment.degraded,
                site_id=event.site_id,
                zone_id=event.zone_id,
                client_hash=event.client_hash,
                qname=event.qname,
            ),
            mode,
        )

    async def _enqueue_threat(
        self,
        event: NormalizedDnsEvent,
        prediction: ThreatPrediction,
        mode: PredictionMode,
    ) -> None:
        runtime = (
            DetectorRuntime.HEURISTIC_FALLBACK
            if mode is PredictionMode.HEURISTIC_FALLBACK
            else DetectorRuntime.QVAC_LOCAL
        )
        payload = WazuhThreatEvent(
            event_type=WazuhEventType.DNS_THREAT,
            event_id=event.event_id,
            timestamp=prediction.created_at,
            site=event.site_id,
            zone=event.zone_id,
            dns=WazuhDnsFields(qname=event.qname),
            threat=WazuhThreatFields(
                type=prediction.threat_type,
                confidence=prediction.confidence,
                severity=prediction.severity,
                reasons=prediction.reasons,
            ),
            detector=WazuhDetectorFields(
                runtime=runtime,
                version=self._settings.detector_version,
            ),
        )
        await self._enqueue(
            OutboxRecord(
                id=uuid5(PREDICTION_ID_NAMESPACE, f"threat:{event.event_id}"),
                event_id=event.event_id,
                prediction_id=prediction.prediction_id,
                created_at=prediction.created_at,
                payload=payload.model_dump_json(),
                status=OutboxStatus.PENDING,
                record_type=WazuhEventType.DNS_THREAT,
            )
        )

    async def _enqueue_qvac_degraded(
        self,
        event: NormalizedDnsEvent,
        prediction: ThreatPrediction,
    ) -> None:
        if self._qvac_degraded_alerted:
            return
        payload = WazuhThreatEvent(
            event_type=WazuhEventType.SENTINEL_OPERATIONAL,
            event_id=event.event_id,
            timestamp=prediction.created_at,
            site=event.site_id,
            zone=event.zone_id,
            dns=WazuhDnsFields(qname=event.qname),
            threat=WazuhThreatFields(
                type=ThreatType.NONE,
                confidence=0.0,
                severity=prediction.severity,
                reasons=["qvac_degraded"],
            ),
            detector=WazuhDetectorFields(
                runtime=DetectorRuntime.HEURISTIC_FALLBACK,
                version=self._settings.detector_version,
            ),
        )
        inserted = await self._enqueue(
            OutboxRecord(
                id=uuid5(PREDICTION_ID_NAMESPACE, "operational:qvac_degraded"),
                event_id=event.event_id,
                prediction_id=prediction.prediction_id,
                created_at=prediction.created_at,
                payload=payload.model_dump_json(),
                status=OutboxStatus.PENDING,
                record_type=WazuhEventType.SENTINEL_OPERATIONAL,
            )
        )
        if inserted:
            self._qvac_degraded_alerted = True

    async def _enqueue(self, record: OutboxRecord) -> bool:
        try:
            return await self._outbox.enqueue(record)
        except OutboxFullError as exc:
            raise KafkaBackpressureError() from exc
