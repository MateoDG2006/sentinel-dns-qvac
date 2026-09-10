"""Lexical, temporal, and brand-distance features for DNS events."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Self

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict, Field, field_validator
from rapidfuzz.distance import DamerauLevenshtein

from app.core.config import Settings
from app.domain.schemas import DnsFeatures, NormalizedDnsEvent, TemporalContext
from app.utils.dns import Qname
from app.utils.text import DomainText


class WeightedSignals(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DgaWeights(WeightedSignals):
    entropy: float = Field(ge=0.0, le=1.0)
    length: float = Field(ge=0.0, le=1.0)
    vowels: float = Field(ge=0.0, le=1.0)
    digits: float = Field(ge=0.0, le=1.0)


class DgaRuleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entropy_min: float = Field(ge=0.0)
    sld_length_min: int = Field(ge=0)
    vowel_ratio_max: float = Field(ge=0.0, le=1.0)
    digit_ratio_min: float = Field(ge=0.0, le=1.0)
    longest_label_max: int = Field(ge=0)
    label_count_max: int = Field(ge=1)
    score_threshold: float = Field(ge=0.0, le=1.0)
    weights: DgaWeights


class TyposquatWeights(WeightedSignals):
    distance: float = Field(ge=0.0, le=1.0)
    homoglyph: float = Field(ge=0.0, le=1.0)
    affix: float = Field(ge=0.0, le=1.0)


class TyposquatRuleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_distance: int = Field(ge=1)
    score_threshold: float = Field(ge=0.0, le=1.0)
    deceptive_prefixes: list[str]
    deceptive_suffixes: list[str]
    weights: TyposquatWeights

    @field_validator("deceptive_prefixes", "deceptive_suffixes")
    @classmethod
    def _normalize_affixes(cls, values: list[str]) -> list[str]:
        return [item.strip().lower() for item in values if item.strip()]


class TunnelingWeights(WeightedSignals):
    long_label: float = Field(ge=0.0, le=1.0)
    uniqueness: float = Field(ge=0.0, le=1.0)
    query_rate: float = Field(ge=0.0, le=1.0)
    entropy: float = Field(ge=0.0, le=1.0)
    txt: float = Field(ge=0.0, le=1.0)


class TunnelingRuleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    longest_label_min: int = Field(ge=0)
    uniqueness_min: float = Field(ge=0.0, le=1.0)
    query_rate_min: float = Field(ge=0.0)
    entropy_min: float = Field(ge=0.0)
    score_threshold: float = Field(ge=0.0, le=1.0)
    weights: TunnelingWeights


class BeaconingWeights(WeightedSignals):
    periodicity: float = Field(ge=0.0, le=1.0)
    low_jitter: float = Field(ge=0.0, le=1.0)
    volume: float = Field(ge=0.0, le=1.0)


class BeaconingRuleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query_count_min: int = Field(ge=1)
    jitter_ratio_max: float = Field(ge=0.0, le=1.0)
    interval_min_ms: float = Field(ge=0.0)
    interval_max_ms: float = Field(ge=0.0)
    score_threshold: float = Field(ge=0.0, le=1.0)
    weights: BeaconingWeights


class SeverityRuleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    medium_min: float = Field(ge=0.0, le=1.0)
    high_min: float = Field(ge=0.0, le=1.0)
    critical_min: float = Field(ge=0.0, le=1.0)


class HomoglyphConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    substitutions: dict[str, str]
    sequences: dict[str, str]


class FeaturesConfig(BaseModel):
    """Versioned heuristic thresholds loaded from config/features.yaml."""

    model_config = ConfigDict(extra="forbid")

    version: str
    suspicious_qtypes: list[str]
    nxdomain_rcode: str
    resolver_error_rcodes: list[str]
    homoglyphs: HomoglyphConfig
    dga: DgaRuleConfig
    typosquatting: TyposquatRuleConfig
    tunneling: TunnelingRuleConfig
    beaconing: BeaconingRuleConfig
    severity: SeverityRuleConfig

    @field_validator("suspicious_qtypes", "resolver_error_rcodes")
    @classmethod
    def _upper_codes(cls, values: list[str]) -> list[str]:
        return [item.strip().upper() for item in values if item.strip()]

    @field_validator("nxdomain_rcode")
    @classmethod
    def _upper_rcode(cls, value: str) -> str:
        return value.strip().upper()

    @classmethod
    def load(cls, path: Path) -> Self:
        return cls.model_validate(YamlMapping.load(path))


class BrandCatalog(BaseModel):
    """Fictional/authorized brands used for typosquatting distance."""

    model_config = ConfigDict(extra="forbid")

    version: str
    brands: list[str] = Field(min_length=1)

    @field_validator("brands")
    @classmethod
    def _normalize_brands(cls, values: list[str]) -> list[str]:
        normalized = [item.strip().lower() for item in values if item.strip()]
        if not normalized:
            raise ValueError("brands.yaml must list at least one brand")
        return normalized

    @classmethod
    def load(cls, path: Path) -> Self:
        return cls.model_validate(YamlMapping.load(path))


class YamlMapping:
    """Load a YAML mapping from disk without exposing a free function."""

    @staticmethod
    def load(path: Path) -> dict[str, Any]:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"YAML mapping required: {path}")
        return raw


class BrandDistance:
    """Damerau-Levenshtein distance from qname tokens to configured brands."""

    def __init__(self, brands: list[str]) -> None:
        self._brands = tuple(brands)

    def minimum(self, qname: str) -> int | None:
        if not self._brands:
            return None
        candidates = self._candidates(qname)
        if not candidates:
            return None
        return min(
            int(DamerauLevenshtein.distance(candidate, brand))
            for candidate in candidates
            for brand in self._brands
        )

    def _candidates(self, qname: str) -> tuple[str, ...]:
        labels = Qname.split_labels(qname)
        names: list[str] = []
        if labels:
            names.append(Qname.sld(qname))
        for label in labels[:-1] if len(labels) > 1 else labels:
            names.append(label)
            names.extend(part for part in label.split("-") if part)
        unique: list[str] = []
        seen: set[str] = set()
        for name in names:
            if name not in seen:
                seen.add(name)
                unique.append(name)
        return tuple(unique)


class FeatureExtractor:
    """Derive DnsFeatures from a normalized event and a one-minute window."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        config: FeaturesConfig | None = None,
        brands: BrandCatalog | None = None,
    ) -> None:
        resolved = settings or Settings.get()
        self._config = config or FeaturesConfig.load(resolved.features_config_path)
        catalog = brands or BrandCatalog.load(resolved.brands_config_path)
        self._brand_distance = BrandDistance(catalog.brands)
        self._suspicious_qtypes = frozenset(self._config.suspicious_qtypes)
        self._resolver_errors = frozenset(self._config.resolver_error_rcodes)
        self._nxdomain = self._config.nxdomain_rcode

    def extract(self, event: NormalizedDnsEvent, history: TemporalContext) -> DnsFeatures:
        labels = Qname.split_labels(event.qname)
        lexical = Qname.without_dots(event.qname)
        query_rate = float(history.query_count_1m)
        uniqueness = (
            min(history.distinct_subdomains_1m / history.query_count_1m, 1.0)
            if history.query_count_1m
            else 0.0
        )
        return DnsFeatures(
            domain_entropy=DomainText.shannon_entropy(lexical),
            domain_length=len(event.qname),
            label_count=len(labels),
            digit_ratio=DomainText.digit_ratio(lexical),
            vowel_ratio=DomainText.vowel_ratio(lexical),
            longest_label_length=max((len(label) for label in labels), default=0),
            subdomain_uniqueness_1m=uniqueness,
            query_rate_1m=query_rate,
            interval_mean_ms=history.interval_mean_ms,
            interval_jitter_ms=history.interval_jitter_ms,
            brand_distance=self._brand_distance.minimum(event.qname),
            suspicious_qtype=event.qtype.strip().upper() in self._suspicious_qtypes,
            nxdomain=event.rcode.strip().upper() == self._nxdomain,
            resolver_error=event.timed_out or event.rcode.strip().upper() in self._resolver_errors,
        )
