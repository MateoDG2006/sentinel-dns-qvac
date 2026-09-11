"""Unit tests for DNS schema validation and IDN normalization."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.domain.schemas import NormalizedDnsEvent, PredictionRequest
from app.utils.dns import Qname


def _event_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_id": uuid4(),
        "event_ts": datetime(2026, 9, 10, 12, 0, tzinfo=UTC),
        "observed_at": datetime(2026, 9, 10, 12, 0, tzinfo=UTC),
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
    return payload


def test_qname_is_lowercased_and_trailing_dot_stripped() -> None:
    event = NormalizedDnsEvent.model_validate(_event_payload(qname="WWW.Example.COM."))
    assert event.qname == "www.example.com"


def test_idn_qname_is_converted_to_punycode() -> None:
    event = NormalizedDnsEvent.model_validate(_event_payload(qname="münchen.example"))
    assert event.qname == "xn--mnchen-3ya.example"
    assert Qname.normalize("bücher.test") == "xn--bcher-kva.test"


def test_qname_rejects_empty_label_and_overlong_name() -> None:
    with pytest.raises(ValidationError):
        NormalizedDnsEvent.model_validate(_event_payload(qname="example..com"))
    with pytest.raises(ValidationError):
        NormalizedDnsEvent.model_validate(_event_payload(qname=("a" * 64) + ".com"))
    with pytest.raises(ValidationError):
        NormalizedDnsEvent.model_validate(_event_payload(qname=("a." * 127) + "com"))


def test_synthetic_must_be_true() -> None:
    with pytest.raises(ValidationError):
        NormalizedDnsEvent.model_validate(_event_payload(synthetic=False))


def test_latency_cannot_be_negative() -> None:
    with pytest.raises(ValidationError):
        NormalizedDnsEvent.model_validate(_event_payload(latency_ms=-0.1))


def test_naive_timestamps_are_rejected() -> None:
    with pytest.raises(ValidationError):
        NormalizedDnsEvent.model_validate(_event_payload(event_ts=datetime(2026, 9, 10, 12, 0)))


def test_prediction_request_accepts_one_to_one_hundred_events() -> None:
    event = NormalizedDnsEvent.model_validate(_event_payload())
    PredictionRequest(events=[event])
    PredictionRequest(events=[event] * 100)
    with pytest.raises(ValidationError):
        PredictionRequest(events=[])
    with pytest.raises(ValidationError):
        PredictionRequest(events=[event] * 101)
