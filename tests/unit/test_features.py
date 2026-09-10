"""Unit tests for lexical DNS features and temporal context mapping."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from app.domain.schemas import NormalizedDnsEvent, TemporalContext
from app.services.feature_extraction import FeatureExtractor
from app.utils.text import DomainText


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
        "query_count_1m": 0,
        "distinct_subdomains_1m": 0,
        "interval_mean_ms": None,
        "interval_jitter_ms": None,
    }
    payload.update(overrides)
    return TemporalContext.model_validate(payload)


def test_shannon_entropy_is_zero_for_repeated_chars_and_two_for_four_unique() -> None:
    assert DomainText.shannon_entropy("aaaa") == pytest.approx(0.0)
    assert DomainText.shannon_entropy("abcd") == pytest.approx(2.0)
    assert DomainText.shannon_entropy("") == 0.0


def test_digit_and_vowel_ratios() -> None:
    assert DomainText.digit_ratio("a1b2") == pytest.approx(0.5)
    assert DomainText.digit_ratio("abcd") == pytest.approx(0.0)
    assert DomainText.vowel_ratio("abba") == pytest.approx(0.5)
    assert DomainText.vowel_ratio("1234") == pytest.approx(0.0)


def test_extractor_maps_lexical_and_rcode_features() -> None:
    extractor = FeatureExtractor()
    features = extractor.extract(
        _event(qname="mail.acmebank.test", qtype="TXT", rcode="NXDOMAIN"),
        _history(),
    )
    assert features.domain_length == len("mail.acmebank.test")
    assert features.label_count == 3
    assert features.longest_label_length == len("acmebank")
    assert features.digit_ratio == pytest.approx(0.0)
    assert 0.0 < features.vowel_ratio < 1.0
    assert features.domain_entropy > 0.0
    assert features.suspicious_qtype is True
    assert features.nxdomain is True
    assert features.resolver_error is False
    assert features.brand_distance == 0


def test_extractor_marks_resolver_errors_and_timeouts() -> None:
    extractor = FeatureExtractor()
    servfail = extractor.extract(_event(rcode="SERVFAIL"), _history())
    timeout = extractor.extract(_event(timed_out=True), _history())
    assert servfail.resolver_error is True
    assert servfail.nxdomain is False
    assert timeout.resolver_error is True


def test_extractor_copies_temporal_context_and_uniqueness() -> None:
    extractor = FeatureExtractor()
    features = extractor.extract(
        _event(),
        _history(
            query_count_1m=20,
            distinct_subdomains_1m=15,
            interval_mean_ms=30_000.0,
            interval_jitter_ms=200.0,
        ),
    )
    assert features.query_rate_1m == pytest.approx(20.0)
    assert features.subdomain_uniqueness_1m == pytest.approx(0.75)
    assert features.interval_mean_ms == pytest.approx(30_000.0)
    assert features.interval_jitter_ms == pytest.approx(200.0)


def test_brand_distance_is_one_for_a_single_edit() -> None:
    extractor = FeatureExtractor()
    exact = extractor.extract(_event(qname="www.acmebank.test"), _history())
    typo = extractor.extract(_event(qname="acmebunk.test"), _history())
    assert exact.brand_distance == 0
    assert typo.brand_distance == 1


def test_dga_like_name_has_higher_entropy_than_a_brand() -> None:
    extractor = FeatureExtractor()
    dga = extractor.extract(_event(qname="xkqpwzlmntabvdfg.test"), _history())
    brand = extractor.extract(_event(qname="northwind.test"), _history())
    assert dga.domain_entropy > brand.domain_entropy
    assert dga.vowel_ratio < brand.vowel_ratio
    assert dga.longest_label_length == 16
