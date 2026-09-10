"""Deterministic QVAC JSON parser tests. No model or network."""

from __future__ import annotations

import pytest

from app.domain.enums import ThreatType
from app.domain.errors import QvacInvalidResponseError
from app.infrastructure.qvac.parser import QvacResponseParser

VALID = '{"threat_type":"dga","score":0.72,"reasons":["high_entropy"]}'
PARSER = QvacResponseParser()


def test_parser_accepts_valid_json() -> None:
    verdict = PARSER.parse(VALID, model_id="local-qwen")
    assert verdict.threat_type is ThreatType.DGA
    assert verdict.score == 0.72
    assert verdict.reasons == ["high_entropy"]
    assert verdict.model_id == "local-qwen"


def test_parser_rejects_truncated_json() -> None:
    truncated = '{"threat_type":"dga","score":0.72,"reasons":['
    with pytest.raises(QvacInvalidResponseError, match="truncated"):
        PARSER.parse(truncated, model_id="local-qwen")


def test_parser_rejects_extra_fields() -> None:
    extra = '{"threat_type":"dga","score":0.72,"reasons":[],"foo":1}'
    with pytest.raises(QvacInvalidResponseError, match="extra fields"):
        PARSER.parse(extra, model_id="local-qwen")


def test_parser_rejects_score_out_of_range() -> None:
    high = '{"threat_type":"dga","score":1.5,"reasons":[]}'
    low = '{"threat_type":"dga","score":-0.01,"reasons":[]}'
    with pytest.raises(QvacInvalidResponseError, match="score is out of range"):
        PARSER.parse(high, model_id="local-qwen")
    with pytest.raises(QvacInvalidResponseError, match="score is out of range"):
        PARSER.parse(low, model_id="local-qwen")
