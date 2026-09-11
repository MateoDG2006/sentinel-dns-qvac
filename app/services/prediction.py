"""Typed prediction stub shared by the webhook until the consumer lands in A5."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import ClassVar
from uuid import uuid4

from app.core.config import Settings
from app.domain.enums import EventSource, PredictionMode, Severity, ThreatType
from app.domain.errors import KafkaBackpressureError
from app.domain.schemas import NormalizedDnsEvent, PredictionResult, ThreatPrediction


class InternalQueue:
    """In-memory depth used for webhook backpressure until a real queue exists."""

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

    def override_depth(self, depth: int) -> None:
        self._depth = depth


class PredictionService:
    """Accept a batch and return heuristic-fallback stubs. No QVAC or Kafka."""

    _STUB_REASON: ClassVar[str] = "heuristic_fallback_stub"

    def __init__(
        self,
        settings: Settings,
        queue: InternalQueue | None = None,
    ) -> None:
        self._settings = settings
        self._queue = queue or InternalQueue(max_events=settings.internal_queue_max_events)

    @property
    def queue(self) -> InternalQueue:
        return self._queue

    async def process_batch(
        self,
        events: list[NormalizedDnsEvent],
        source: EventSource,
    ) -> list[PredictionResult]:
        if self._queue.is_over_capacity():
            raise KafkaBackpressureError()
        created_at = datetime.now(UTC)
        results: list[PredictionResult] = []
        for event in events:
            prediction = ThreatPrediction(
                prediction_id=uuid4(),
                event_id=event.event_id,
                created_at=created_at,
                detector_version=self._settings.detector_version,
                model_id=None,
                threat_type=ThreatType.NONE,
                confidence=0.0,
                severity=Severity.LOW,
                reasons=[self._STUB_REASON],
                heuristic_score=0.0,
                qvac_score=None,
                degraded=True,
                site_id=event.site_id,
                zone_id=event.zone_id,
                client_hash=event.client_hash,
                qname=event.qname,
            )
            results.append(
                PredictionResult(
                    prediction=prediction,
                    source=source,
                    mode=PredictionMode.HEURISTIC_FALLBACK,
                )
            )
        return results
