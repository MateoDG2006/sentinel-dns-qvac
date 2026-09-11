"""Offline mixed_demo: planned families reach the shared PredictionService."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.config import Settings
from app.domain.enums import EventSource, ThreatType
from app.services.lab_fidelity import LabBatchSampler
from app.services.prediction import PredictionService
from simulator.main import ground_truth_labels, plan, to_event
from simulator.profiles import DEFAULT_ZONE, SITES
from simulator.scenarios import get_scenario

_FAMILIES = {
    ThreatType.DGA.value,
    ThreatType.TYPOSQUATTING.value,
    ThreatType.DNS_TUNNELING.value,
    ThreatType.BEACONING.value,
}


async def test_mixed_demo_plan_covers_four_threat_families() -> None:
    spec = get_scenario("mixed_demo")
    planned = plan(
        "mixed_demo",
        sites=[SITES[0]],
        zones=[DEFAULT_ZONE],
        rate_per_s=spec.default_rate_per_s,
        duration_s=spec.default_duration_s,
        seed=42,
        run_id="e2e-mixed",
    )
    labels = {str(ground_truth_labels(item).get("threat_type") or "none") for item in planned}
    assert _FAMILIES <= labels


async def test_mixed_demo_sample_is_scored_by_shared_prediction_service() -> None:
    spec = get_scenario("mixed_demo")
    planned = plan(
        "mixed_demo",
        sites=[SITES[0]],
        zones=[DEFAULT_ZONE],
        rate_per_s=spec.default_rate_per_s,
        duration_s=min(spec.default_duration_s, 120.0),
        seed=42,
        run_id="e2e-score",
    )
    sampled = LabBatchSampler.take(planned, 40)
    origin = datetime(2026, 9, 11, tzinfo=UTC)
    events = [
        to_event(item, now=origin + timedelta(seconds=item.query.offset_s)) for item in sampled
    ]
    results = await PredictionService(Settings()).process_batch(events, EventSource.KAFKA)
    assert len(results) == len(events)
    predicted = {item.prediction.threat_type.value for item in results}
    assert predicted
    assert all(result.source is EventSource.KAFKA for result in results)
