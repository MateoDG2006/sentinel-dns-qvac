"""Enrichment fallback uses a fake QvacInferencePort. No SDK, no network."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from app.core.config import Settings
from app.domain.enums import DependencyStatus, Severity, ThreatType
from app.domain.errors import QvacInvalidResponseError, QvacTimeoutError, QvacUnavailableError
from app.domain.schemas import (
    DependencyHealth,
    DnsFeatures,
    HeuristicVerdict,
    QvacCandidate,
    QvacVerdict,
)
from app.services.qvac_enrichment import QvacEnrichmentService
from app.utils.time import UtcDateTime


def _features() -> DnsFeatures:
    return DnsFeatures(
        domain_entropy=3.2,
        domain_length=18,
        label_count=2,
        digit_ratio=0.1,
        vowel_ratio=0.3,
        longest_label_length=10,
        subdomain_uniqueness_1m=0.2,
        query_rate_1m=1.0,
        interval_mean_ms=None,
        interval_jitter_ms=None,
        brand_distance=None,
        suspicious_qtype=False,
        nxdomain=False,
        resolver_error=False,
    )


def _heuristic(score: float) -> HeuristicVerdict:
    return HeuristicVerdict(
        threat_type=ThreatType.DGA,
        score=score,
        severity=Severity.MEDIUM,
        reasons=["high_entropy"],
    )


def _candidate(heuristic: HeuristicVerdict) -> QvacCandidate:
    return QvacCandidate(
        event_id=uuid4(),
        qname="xkqpwzlmntabvdfg.test",
        qtype="A",
        rcode="NXDOMAIN",
        features=_features(),
        heuristic_score=heuristic.score,
        heuristic_threat_type=heuristic.threat_type,
        heuristic_reasons=heuristic.reasons,
    )


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


async def test_enrichment_skips_hot_path_without_calling_port() -> None:
    port = FakeQvacPort(error=QvacUnavailableError())
    service = QvacEnrichmentService(port, settings=Settings())
    heuristic = _heuristic(0.95)
    result = await service.enrich(_candidate(heuristic), heuristic)
    assert port.calls == 0
    assert result.qvac is None
    assert result.degraded is False
    assert result.heuristic is heuristic


async def test_enrichment_returns_qvac_verdict_on_success() -> None:
    verdict = QvacVerdict(
        threat_type=ThreatType.DGA,
        score=0.81,
        reasons=["model_dga"],
        model_id="fake",
    )
    port = FakeQvacPort(verdict=verdict)
    service = QvacEnrichmentService(port, settings=Settings())
    heuristic = _heuristic(0.70)
    result = await service.enrich(_candidate(heuristic), heuristic)
    assert port.calls == 1
    assert result.qvac == verdict
    assert result.degraded is False


async def test_enrichment_falls_back_when_qvac_times_out() -> None:
    port = FakeQvacPort(error=QvacTimeoutError())
    await _assert_degraded(port)


async def test_enrichment_falls_back_when_qvac_unavailable() -> None:
    port = FakeQvacPort(error=QvacUnavailableError())
    await _assert_degraded(port)


async def test_enrichment_falls_back_when_json_invalid() -> None:
    port = FakeQvacPort(error=QvacInvalidResponseError())
    await _assert_degraded(port)


async def _assert_degraded(port: FakeQvacPort) -> None:
    service = QvacEnrichmentService(port, settings=Settings())
    heuristic = _heuristic(0.70)
    result = await service.enrich(_candidate(heuristic), heuristic)
    assert port.calls == 1
    assert result.qvac is None
    assert result.degraded is True
    assert result.heuristic is heuristic
