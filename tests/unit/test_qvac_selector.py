"""QVAC candidate selector bands from Settings thresholds."""

from __future__ import annotations

from app.core.config import Settings
from app.domain.enums import Severity, ThreatType
from app.domain.schemas import HeuristicVerdict
from app.services.qvac_enrichment import QvacCandidateSelector


def _verdict(score: float) -> HeuristicVerdict:
    return HeuristicVerdict(
        threat_type=ThreatType.DGA if score >= 0.45 else ThreatType.NONE,
        score=score,
        severity=Severity.HIGH if score >= 0.90 else Severity.MEDIUM,
        reasons=["unit-test"],
    )


def test_selector_skips_high_confidence_hot_path() -> None:
    selector = QvacCandidateSelector(Settings())
    assert selector.should_enrich(_verdict(0.90)) is False
    assert selector.should_enrich(_verdict(1.00)) is False


def test_selector_enriches_ambiguous_band() -> None:
    selector = QvacCandidateSelector(Settings())
    assert selector.should_enrich(_verdict(0.45)) is True
    assert selector.should_enrich(_verdict(0.89)) is True


def test_selector_skips_low_score() -> None:
    selector = QvacCandidateSelector(Settings())
    assert selector.should_enrich(_verdict(0.44)) is False
    assert selector.should_enrich(_verdict(0.00)) is False


def test_selector_respects_qvac_enabled_flag() -> None:
    selector = QvacCandidateSelector(Settings(qvac_enabled=False))
    assert selector.should_enrich(_verdict(0.70)) is False
