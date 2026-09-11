"""Pydantic contracts for DNS events, predictions, QoE, and receipts."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

from app.constants.api import PREDICTION_BATCH_MAX
from app.constants.dns import QNAME_MAX_LENGTH, SCHEMA_VERSION
from app.domain.enums import (
    DependencyStatus,
    DetectorRuntime,
    EventSource,
    OutboxStatus,
    PredictionMode,
    QoePrimaryCause,
    QoeStatus,
    Severity,
    ThreatType,
    WazuhEventType,
)
from app.utils.dns import Qname
from app.utils.time import UtcDateTime


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class NormalizedDnsEvent(FrozenModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    event_id: UUID
    event_ts: AwareDatetime
    observed_at: AwareDatetime
    site_id: str = Field(min_length=1)
    zone_id: str = Field(min_length=1)
    resolver_id: str = Field(min_length=1)
    client_hash: str = Field(min_length=1)
    qname: str = Field(min_length=1, max_length=QNAME_MAX_LENGTH)
    qtype: str = Field(min_length=1)
    rcode: str = Field(min_length=1)
    latency_ms: float | None = Field(default=None, ge=0.0)
    response_bytes: int | None = Field(default=None, ge=0)
    timed_out: bool = False
    synthetic: Literal[True] = True

    @field_validator("event_ts", "observed_at")
    @classmethod
    def _utc_timestamps(cls, value: datetime) -> datetime:
        return UtcDateTime.ensure(value)

    @field_validator("qname")
    @classmethod
    def _normalize_qname(cls, value: str) -> str:
        return Qname.normalize(value)


class DnsFeatures(FrozenModel):
    domain_entropy: float = Field(ge=0.0)
    domain_length: int = Field(ge=0)
    label_count: int = Field(ge=0)
    digit_ratio: float = Field(ge=0.0, le=1.0)
    vowel_ratio: float = Field(ge=0.0, le=1.0)
    longest_label_length: int = Field(ge=0)
    subdomain_uniqueness_1m: float = Field(ge=0.0, le=1.0)
    query_rate_1m: float = Field(ge=0.0)
    interval_mean_ms: float | None = Field(default=None, ge=0.0)
    interval_jitter_ms: float | None = Field(default=None, ge=0.0)
    brand_distance: int | None = Field(default=None, ge=0)
    suspicious_qtype: bool
    nxdomain: bool
    resolver_error: bool


class TemporalContext(FrozenModel):
    query_count_1m: int = Field(default=0, ge=0)
    distinct_subdomains_1m: int = Field(default=0, ge=0)
    interval_mean_ms: float | None = Field(default=None, ge=0.0)
    interval_jitter_ms: float | None = Field(default=None, ge=0.0)


class HeuristicVerdict(FrozenModel):
    threat_type: ThreatType
    score: float = Field(ge=0.0, le=1.0)
    severity: Severity
    reasons: list[str] = Field(default_factory=list)


class QvacCandidate(FrozenModel):
    event_id: UUID
    qname: str
    qtype: str
    rcode: str
    features: DnsFeatures
    heuristic_score: float = Field(ge=0.0, le=1.0)
    heuristic_threat_type: ThreatType
    heuristic_reasons: list[str] = Field(default_factory=list)


class QvacVerdict(FrozenModel):
    threat_type: ThreatType
    score: float = Field(ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)
    model_id: str = Field(min_length=1)


class ThreatPrediction(FrozenModel):
    prediction_id: UUID
    event_id: UUID
    created_at: AwareDatetime
    detector_version: str = Field(min_length=1)
    model_id: str | None = None
    threat_type: ThreatType
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    reasons: list[str]
    heuristic_score: float = Field(ge=0.0, le=1.0)
    qvac_score: float | None = Field(default=None, ge=0.0, le=1.0)
    degraded: bool = False
    site_id: str = Field(min_length=1)
    zone_id: str = Field(min_length=1)
    client_hash: str = Field(min_length=1)
    qname: str = Field(min_length=1)

    @field_validator("created_at")
    @classmethod
    def _utc_created_at(cls, value: datetime) -> datetime:
        return UtcDateTime.ensure(value)

    @field_validator("qname")
    @classmethod
    def _normalize_qname(cls, value: str) -> str:
        return Qname.normalize(value)


class PredictionResult(FrozenModel):
    prediction: ThreatPrediction
    source: EventSource
    mode: PredictionMode


class PredictionRequest(FrozenModel):
    events: list[NormalizedDnsEvent] = Field(min_length=1, max_length=PREDICTION_BATCH_MAX)
    correlation_id: UUID | None = None


class PredictionReceipt(FrozenModel):
    correlation_id: UUID
    accepted: int = Field(ge=0)
    rejected: int = Field(ge=0)
    result_ids: list[UUID]
    mode: PredictionMode


class WazuhDnsFields(FrozenModel):
    qname: str


class WazuhThreatFields(FrozenModel):
    type: ThreatType
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    reasons: list[str]


class WazuhDetectorFields(FrozenModel):
    runtime: DetectorRuntime
    version: str = Field(min_length=1)


class WazuhThreatEvent(FrozenModel):
    integration: Literal["sentinel-dns"] = "sentinel-dns"
    event_type: WazuhEventType
    event_id: UUID
    timestamp: AwareDatetime
    site: str = Field(min_length=1)
    zone: str = Field(min_length=1)
    dns: WazuhDnsFields
    threat: WazuhThreatFields
    detector: WazuhDetectorFields

    @field_validator("timestamp")
    @classmethod
    def _utc_timestamp(cls, value: datetime) -> datetime:
        return UtcDateTime.ensure(value)


class QoeWindow(FrozenModel):
    window_start: AwareDatetime
    site_id: str = Field(min_length=1)
    zone_id: str = Field(min_length=1)
    sample_count: int = Field(ge=0)
    latency_p50_ms: float = Field(ge=0.0)
    latency_p95_ms: float = Field(ge=0.0)
    latency_p99_ms: float = Field(ge=0.0)
    nxdomain_rate: float = Field(ge=0.0, le=1.0)
    servfail_rate: float = Field(ge=0.0, le=1.0)
    timeout_rate: float = Field(ge=0.0, le=1.0)
    saturation_index: float = Field(ge=0.0, le=1.0)
    latency_score: float = Field(ge=0.0, le=100.0)
    resolution_score: float = Field(ge=0.0, le=100.0)
    saturation_score: float = Field(ge=0.0, le=100.0)
    qoe_score: float = Field(ge=0.0, le=100.0)
    status: QoeStatus
    primary_cause: QoePrimaryCause
    calculation_version: str = Field(min_length=1)
    updated_at: AwareDatetime

    @field_validator("window_start", "updated_at")
    @classmethod
    def _utc_window_times(cls, value: datetime) -> datetime:
        return UtcDateTime.ensure(value)


class DependencyHealth(FrozenModel):
    name: str = Field(min_length=1)
    status: DependencyStatus
    detail: str | None = None
    checked_at: AwareDatetime

    @field_validator("checked_at")
    @classmethod
    def _utc_checked_at(cls, value: datetime) -> datetime:
        return UtcDateTime.ensure(value)


class DeliveryResult(FrozenModel):
    accepted: int = Field(ge=0)
    rejected: int = Field(ge=0)
    retryable: bool = False
    status_code: int | None = None
    retry_after_seconds: float | None = Field(default=None, ge=0.0)
    reason: str | None = None


class OutboxRecord(FrozenModel):
    id: UUID
    event_id: UUID
    prediction_id: UUID | None = None
    created_at: AwareDatetime
    payload: str = Field(min_length=1)
    status: OutboxStatus
    attempts: int = Field(default=0, ge=0)
    next_retry_at: AwareDatetime | None = None
    last_reason: str | None = None
    record_type: WazuhEventType

    @field_validator("created_at", "next_retry_at")
    @classmethod
    def _utc_outbox_times(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return UtcDateTime.ensure(value)
