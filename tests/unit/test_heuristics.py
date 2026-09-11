"""Unit tests for DGA, typosquatting, tunneling, and beaconing heuristics."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.domain.enums import Severity, ThreatType
from app.domain.schemas import HeuristicVerdict, NormalizedDnsEvent, TemporalContext
from app.services.feature_extraction import FeatureExtractor
from app.services.heuristics import HeuristicThreatDetector


def _event(**overrides: Any) -> NormalizedDnsEvent:
    payload: dict[str, Any] = {
        "event_id": uuid4(),
        "event_ts": datetime(2026, 9, 10, 12, 0, tzinfo=UTC),
        "observed_at": datetime(2026, 9, 10, 12, 0, tzinfo=UTC),
        "site_id": "pop-1",
        "zone_id": "zone-a",
        "resolver_id": "resolver-1",
        "client_hash": "client-hash-1",
        "qname": "www.acmebank.test",
        "qtype": "A",
        "rcode": "NOERROR",
        "latency_ms": 25.0,
        "response_bytes": 128,
        "timed_out": False,
        "synthetic": True,
    }
    payload.update(overrides)
    return NormalizedDnsEvent.model_validate(payload)


def _history(**overrides: Any) -> TemporalContext:
    payload: dict[str, Any] = {
        "query_count_1m": 1,
        "distinct_subdomains_1m": 1,
        "interval_mean_ms": None,
        "interval_jitter_ms": None,
    }
    payload.update(overrides)
    return TemporalContext.model_validate(payload)


class _Detector:
    def __init__(self) -> None:
        self.extractor = FeatureExtractor()
        self.detector = HeuristicThreatDetector()

    def evaluate(self, qname: str, **kwargs: Any) -> HeuristicVerdict:
        history_keys = {
            "query_count_1m",
            "distinct_subdomains_1m",
            "interval_mean_ms",
            "interval_jitter_ms",
        }
        history = _history(**{key: kwargs.pop(key) for key in list(kwargs) if key in history_keys})
        event = _event(qname=qname, **kwargs)
        features = self.extractor.extract(event, history)
        return self.detector.evaluate(event, features)


def test_dga_positive_high_entropy_long_label() -> None:
    verdict = _Detector().evaluate("xkqpwzlmntabvdfg.test", rcode="NXDOMAIN")
    assert verdict.threat_type is ThreatType.DGA
    assert verdict.score >= 0.55
    assert "high_entropy" in verdict.reasons
    assert "atypical_length" in verdict.reasons
    assert "low_vowel_ratio" in verdict.reasons
    assert verdict.severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}


def test_dga_negative_dictionary_brand() -> None:
    verdict = _Detector().evaluate("portal.northwind.test")
    assert verdict.threat_type is not ThreatType.DGA


def test_typosquatting_positive_single_edit() -> None:
    verdict = _Detector().evaluate("acmebunk.test")
    assert verdict.threat_type is ThreatType.TYPOSQUATTING
    assert "close_brand_distance" in verdict.reasons
    assert verdict.score >= 0.50


def test_typosquatting_positive_homoglyph_and_affix() -> None:
    detector = _Detector()
    homoglyph = detector.evaluate("acmeb4nk.test")
    affix = detector.evaluate("login-acmebank.test")
    assert homoglyph.threat_type is ThreatType.TYPOSQUATTING
    assert "homoglyph" in homoglyph.reasons
    assert affix.threat_type is ThreatType.TYPOSQUATTING
    assert "deceptive_affix" in affix.reasons


def test_typosquatting_negative_exact_authorized_brand() -> None:
    verdict = _Detector().evaluate("www.acmebank.test")
    assert verdict.threat_type is not ThreatType.TYPOSQUATTING
    assert verdict.threat_type is ThreatType.NONE


def test_tunneling_positive_long_unique_txt() -> None:
    label = "k7qm2p9x0v4n8w3z5t1y6c2h9b4d8f3s5a7eqrxx"
    assert len(label) >= 36
    verdict = _Detector().evaluate(
        f"{label}.tunnel.test",
        qtype="TXT",
        query_count_1m=40,
        distinct_subdomains_1m=36,
    )
    assert verdict.threat_type is ThreatType.DNS_TUNNELING
    assert "long_subdomain_label" in verdict.reasons
    assert "high_subdomain_uniqueness" in verdict.reasons
    assert "suspicious_qtype" in verdict.reasons
    assert verdict.score >= 0.55


def test_tunneling_negative_short_a_query() -> None:
    verdict = _Detector().evaluate(
        "www.acmebank.test",
        qtype="A",
        query_count_1m=4,
        distinct_subdomains_1m=1,
    )
    assert verdict.threat_type is not ThreatType.DNS_TUNNELING


def test_beaconing_positive_periodic_low_jitter() -> None:
    verdict = _Detector().evaluate(
        "status.northwind.test",
        query_count_1m=12,
        distinct_subdomains_1m=1,
        interval_mean_ms=30_000.0,
        interval_jitter_ms=180.0,
    )
    assert verdict.threat_type is ThreatType.BEACONING
    assert "periodic_interval" in verdict.reasons
    assert "low_jitter" in verdict.reasons
    assert verdict.score >= 0.70


def test_beaconing_negative_high_jitter_or_sparse() -> None:
    detector = _Detector()
    jittery = detector.evaluate(
        "status.northwind.test",
        query_count_1m=12,
        distinct_subdomains_1m=1,
        interval_mean_ms=30_000.0,
        interval_jitter_ms=18_000.0,
    )
    sparse = detector.evaluate(
        "status.northwind.test",
        query_count_1m=2,
        distinct_subdomains_1m=1,
        interval_mean_ms=30_000.0,
        interval_jitter_ms=50.0,
    )
    assert jittery.threat_type is not ThreatType.BEACONING
    assert sparse.threat_type is not ThreatType.BEACONING
    assert jittery.threat_type is ThreatType.NONE
    assert sparse.threat_type is ThreatType.NONE
