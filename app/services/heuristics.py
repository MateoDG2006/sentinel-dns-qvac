"""Local heuristic rules for DGA, typosquatting, tunneling, and beaconing."""

from __future__ import annotations

from app.core.config import Settings
from app.domain.enums import Severity, ThreatType
from app.domain.schemas import DnsFeatures, HeuristicVerdict, NormalizedDnsEvent
from app.services.feature_extraction import FeaturesConfig
from app.utils.dns import Qname
from app.utils.text import DomainText, HomoglyphFolder


class AffixMatcher:
    """Detect deceptive prefixes/suffixes used to impersonate a brand."""

    def __init__(self, prefixes: list[str], suffixes: list[str]) -> None:
        self._prefixes = frozenset(prefixes)
        self._suffixes = frozenset(suffixes)

    def match(self, qname: str) -> bool:
        labels = Qname.split_labels(qname)
        body = labels[:-1] if len(labels) > 1 else labels
        for label in body:
            if label in self._prefixes:
                return True
            parts = [part for part in label.split("-") if part]
            if len(parts) >= 2 and (parts[0] in self._prefixes or parts[-1] in self._suffixes):
                return True
        return False


class HeuristicThreatDetector:
    """Score four threat families from extracted features and YAML thresholds."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        config: FeaturesConfig | None = None,
    ) -> None:
        resolved = settings or Settings.get()
        self._config = config or FeaturesConfig.load(resolved.features_config_path)
        self._homoglyphs = HomoglyphFolder(
            self._config.homoglyphs.substitutions,
            self._config.homoglyphs.sequences,
        )
        self._affixes = AffixMatcher(
            self._config.typosquatting.deceptive_prefixes,
            self._config.typosquatting.deceptive_suffixes,
        )

    def evaluate(self, event: NormalizedDnsEvent, features: DnsFeatures) -> HeuristicVerdict:
        scored = (
            self._score_dga(event, features),
            self._score_typosquatting(event, features),
            self._score_tunneling(features),
            self._score_beaconing(features),
        )
        classified = [item for item in scored if item[1] >= self._threshold_for(item[0])]
        if not classified:
            _threat, score, _reasons = max(scored, key=lambda item: item[1])
            return HeuristicVerdict(
                threat_type=ThreatType.NONE,
                score=score,
                severity=Severity.LOW,
                reasons=[],
            )
        threat_type, score, reasons = max(classified, key=lambda item: item[1])
        return HeuristicVerdict(
            threat_type=threat_type,
            score=min(score, 1.0),
            severity=self._severity(score),
            reasons=reasons,
        )

    def _threshold_for(self, threat_type: ThreatType) -> float:
        if threat_type is ThreatType.DGA:
            return self._config.dga.score_threshold
        if threat_type is ThreatType.TYPOSQUATTING:
            return self._config.typosquatting.score_threshold
        if threat_type is ThreatType.DNS_TUNNELING:
            return self._config.tunneling.score_threshold
        if threat_type is ThreatType.BEACONING:
            return self._config.beaconing.score_threshold
        return 1.0

    def _severity(self, score: float) -> Severity:
        rules = self._config.severity
        if score >= rules.critical_min:
            return Severity.CRITICAL
        if score >= rules.high_min:
            return Severity.HIGH
        if score >= rules.medium_min:
            return Severity.MEDIUM
        return Severity.LOW

    def _score_dga(
        self, event: NormalizedDnsEvent, features: DnsFeatures
    ) -> tuple[ThreatType, float, list[str]]:
        rule = self._config.dga
        if (
            features.longest_label_length > rule.longest_label_max
            or features.label_count > rule.label_count_max
        ):
            return ThreatType.DGA, 0.0, []
        sld = Qname.sld(event.qname).replace("-", "")
        entropy = DomainText.shannon_entropy(sld)
        vowel_ratio = DomainText.vowel_ratio(sld)
        digit_ratio = DomainText.digit_ratio(sld)
        has_entropy = entropy >= rule.entropy_min
        has_length = len(sld) >= rule.sld_length_min
        if not has_entropy or not has_length:
            return ThreatType.DGA, 0.0, []
        score = rule.weights.entropy + rule.weights.length
        reasons = ["high_entropy", "atypical_length"]
        if vowel_ratio <= rule.vowel_ratio_max:
            score += rule.weights.vowels
            reasons.append("low_vowel_ratio")
        if digit_ratio >= rule.digit_ratio_min:
            score += rule.weights.digits
            reasons.append("high_digit_ratio")
        return ThreatType.DGA, min(score, 1.0), reasons

    def _score_typosquatting(
        self, event: NormalizedDnsEvent, features: DnsFeatures
    ) -> tuple[ThreatType, float, list[str]]:
        rule = self._config.typosquatting
        distance = features.brand_distance
        if distance is None:
            return ThreatType.TYPOSQUATTING, 0.0, []
        affix = self._affixes.match(event.qname)
        homoglyph = self._has_homoglyph(event.qname)
        close = 1 <= distance <= rule.max_distance
        impersonation = distance == 0 and (affix or homoglyph)
        if not close and not impersonation:
            return ThreatType.TYPOSQUATTING, 0.0, []
        score = 0.0
        reasons: list[str] = []
        if close:
            closeness = 1.0 - ((distance - 1) / rule.max_distance)
            score += rule.weights.distance * closeness
            reasons.append("close_brand_distance")
        elif impersonation:
            score += rule.weights.distance
            reasons.append("brand_impersonation")
        if homoglyph:
            score += rule.weights.homoglyph
            reasons.append("homoglyph")
        if affix:
            score += rule.weights.affix
            reasons.append("deceptive_affix")
        return ThreatType.TYPOSQUATTING, min(score, 1.0), reasons

    def _score_tunneling(self, features: DnsFeatures) -> tuple[ThreatType, float, list[str]]:
        rule = self._config.tunneling
        score = 0.0
        reasons: list[str] = []
        if features.longest_label_length >= rule.longest_label_min:
            score += rule.weights.long_label
            reasons.append("long_subdomain_label")
        if features.subdomain_uniqueness_1m >= rule.uniqueness_min:
            score += rule.weights.uniqueness
            reasons.append("high_subdomain_uniqueness")
        if features.query_rate_1m >= rule.query_rate_min:
            score += rule.weights.query_rate
            reasons.append("high_query_rate")
        if features.domain_entropy >= rule.entropy_min:
            score += rule.weights.entropy
            reasons.append("high_entropy")
        if features.suspicious_qtype:
            score += rule.weights.txt
            reasons.append("suspicious_qtype")
        return ThreatType.DNS_TUNNELING, min(score, 1.0), reasons

    def _score_beaconing(self, features: DnsFeatures) -> tuple[ThreatType, float, list[str]]:
        rule = self._config.beaconing
        if (
            features.query_rate_1m < rule.query_count_min
            or features.interval_mean_ms is None
            or features.interval_jitter_ms is None
        ):
            return ThreatType.BEACONING, 0.0, []
        mean = features.interval_mean_ms
        if mean <= 0.0:
            return ThreatType.BEACONING, 0.0, []
        score = 0.0
        reasons: list[str] = []
        if rule.interval_min_ms <= mean <= rule.interval_max_ms:
            score += rule.weights.periodicity
            reasons.append("periodic_interval")
        jitter_ratio = features.interval_jitter_ms / mean
        if jitter_ratio <= rule.jitter_ratio_max:
            score += rule.weights.low_jitter
            reasons.append("low_jitter")
        score += rule.weights.volume
        reasons.append("repeated_queries")
        return ThreatType.BEACONING, min(score, 1.0), reasons

    def _has_homoglyph(self, qname: str) -> bool:
        if self._homoglyphs.contains_mapped_glyph(Qname.without_dots(qname)):
            return True
        return any(label.startswith("xn--") for label in Qname.split_labels(qname))
