"""Build a compact synthetic batch and score detector output against ground truth.

Uses C1's simulator generators. Ground truth never enters NormalizedDnsEvent.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, Field

from app.constants.lab import (
    DEFAULT_DURATION_S,
    DEFAULT_LIMIT,
    DEFAULT_SEED,
    MAX_DURATION_S,
    MAX_LIMIT,
    THREAT_ORDER,
)
from app.domain.enums import EventSource
from app.domain.schemas import NormalizedDnsEvent, PredictionResult
from app.services.prediction import PredictionService
from simulator.main import PlannedEvent, ground_truth_labels, plan, to_event
from simulator.profiles import DEFAULT_ZONE, SITES
from simulator.scenarios import get_scenario, list_scenarios


class LabCatalogItem(BaseModel):
    name: str
    description: str
    default_rate_per_s: float
    default_duration_s: float


class LabEvaluateRequest(BaseModel):
    scenario: str
    seed: int = Field(default=DEFAULT_SEED, ge=0)
    limit: int = Field(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT)
    duration_s: float = Field(default=DEFAULT_DURATION_S, gt=0.0, le=MAX_DURATION_S)


class LabRow(BaseModel):
    event_id: str
    qname: str
    qtype: str
    rcode: str
    expected_threat: str
    predicted_threat: str
    match: bool
    mode: str
    heuristic_score: float
    qvac_score: float | None
    qvac_used: bool
    confidence: float
    degraded: bool
    reasons: list[str]
    scenario: str
    technique: str | None


class LabSummary(BaseModel):
    total: int
    matches: int
    accuracy: float
    qvac_used: int
    hybrid: int
    heuristic_fallback: int
    degraded: int
    by_expected: dict[str, dict[str, int]]


class LabEvaluateResponse(BaseModel):
    scenario: str
    seed: int
    duration_s: float
    planned: int
    sampled: int
    summary: LabSummary
    rows: list[LabRow]


class LabBatchSampler:
    """Round-robin across threat labels so a short batch still covers families."""

    @staticmethod
    def take(items: list[PlannedEvent], limit: int) -> list[PlannedEvent]:
        buckets: dict[str, list[PlannedEvent]] = defaultdict(list)
        for item in items:
            buckets[item.query.ground_truth.threat_type].append(item)
        picked: list[PlannedEvent] = []
        indexes = {key: 0 for key in buckets}
        order = [key for key in THREAT_ORDER if key in buckets]
        order.extend(sorted(key for key in buckets if key not in order))
        while len(picked) < limit:
            progressed = False
            for key in order:
                group = buckets[key]
                cursor = indexes[key]
                if cursor < len(group):
                    picked.append(group[cursor])
                    indexes[key] = cursor + 1
                    progressed = True
                    if len(picked) >= limit:
                        break
            if not progressed:
                break
        return picked


class LabFidelityService:
    """Local evaluation harness. Does not change the webhook 202 contract."""

    def catalog(self) -> list[LabCatalogItem]:
        items: list[LabCatalogItem] = []
        for name in list_scenarios():
            spec = get_scenario(name)
            items.append(
                LabCatalogItem(
                    name=name,
                    description=spec.description,
                    default_rate_per_s=spec.default_rate_per_s,
                    default_duration_s=spec.default_duration_s,
                )
            )
        return items

    async def evaluate(
        self,
        request: LabEvaluateRequest,
        service: PredictionService,
    ) -> LabEvaluateResponse:
        spec = get_scenario(request.scenario)
        planned = plan(
            request.scenario,
            sites=[SITES[0]],
            zones=[DEFAULT_ZONE],
            rate_per_s=spec.default_rate_per_s,
            duration_s=request.duration_s,
            seed=request.seed,
        )
        sampled = LabBatchSampler.take(planned, request.limit)
        if not sampled:
            raise ValueError("el escenario no produjo eventos en esa ventana")
        now = datetime.now(UTC)
        events: list[NormalizedDnsEvent] = []
        labels: list[dict[str, str | None]] = []
        for item in sampled:
            event = to_event(item, now=now).model_copy(update={"event_id": uuid4()})
            events.append(event)
            raw = ground_truth_labels(item)
            technique = raw.get("technique")
            labels.append(
                {
                    "expected_threat": str(raw.get("threat_type") or "none"),
                    "scenario": str(raw.get("scenario") or request.scenario),
                    "technique": technique if isinstance(technique, str) else None,
                }
            )
        results = await service.process_batch(events, EventSource.WEBHOOK)
        rows = [
            self._row(event, result, label)
            for event, result, label in zip(events, results, labels, strict=True)
        ]
        return LabEvaluateResponse(
            scenario=request.scenario,
            seed=request.seed,
            duration_s=request.duration_s,
            planned=len(planned),
            sampled=len(rows),
            summary=self._summary(rows),
            rows=rows,
        )

    @staticmethod
    def _row(
        event: NormalizedDnsEvent,
        result: PredictionResult,
        label: dict[str, str | None],
    ) -> LabRow:
        predicted = result.prediction.threat_type.value
        expected = label["expected_threat"] or "none"
        qvac_score = result.prediction.qvac_score
        return LabRow(
            event_id=str(event.event_id),
            qname=event.qname,
            qtype=event.qtype,
            rcode=event.rcode,
            expected_threat=expected,
            predicted_threat=predicted,
            match=predicted == expected,
            mode=result.mode.value,
            heuristic_score=result.prediction.heuristic_score,
            qvac_score=qvac_score,
            qvac_used=qvac_score is not None,
            confidence=result.prediction.confidence,
            degraded=result.prediction.degraded,
            reasons=list(result.prediction.reasons),
            scenario=label["scenario"] or "",
            technique=label["technique"],
        )

    @staticmethod
    def _summary(rows: list[LabRow]) -> LabSummary:
        matches = sum(1 for row in rows if row.match)
        total = len(rows)
        matrix: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for row in rows:
            matrix[row.expected_threat][row.predicted_threat] += 1
        return LabSummary(
            total=total,
            matches=matches,
            accuracy=(matches / total) if total else 0.0,
            qvac_used=sum(1 for row in rows if row.qvac_used),
            hybrid=sum(1 for row in rows if row.mode == "hybrid"),
            heuristic_fallback=sum(1 for row in rows if row.mode == "heuristic_fallback"),
            degraded=sum(1 for row in rows if row.degraded),
            by_expected={key: dict(value) for key, value in matrix.items()},
        )
