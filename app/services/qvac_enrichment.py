"""Candidate selection and QVAC enrichment with heuristic fallback."""

from __future__ import annotations

import logging

from app.core.config import Settings
from app.domain.errors import QvacInvalidResponseError, QvacTimeoutError, QvacUnavailableError
from app.domain.ports import QvacInferencePort
from app.domain.schemas import HeuristicVerdict, QvacCandidate, QvacVerdict


class QvacCandidateSelector:
    """Decide whether ambiguous heuristic scores should take the QVAC hot path."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings.get()

    def should_enrich(self, verdict: HeuristicVerdict) -> bool:
        if not self._settings.qvac_enabled:
            return False
        score = verdict.score
        if score >= self._settings.heuristic_alert_threshold:
            return False
        return score >= self._settings.heuristic_qvac_min_score


class QvacEnrichmentResult:
    """Heuristic path plus optional QVAC verdict. PredictionService (A5) assembles predictions."""

    def __init__(
        self,
        *,
        heuristic: HeuristicVerdict,
        qvac: QvacVerdict | None,
        degraded: bool,
    ) -> None:
        self.heuristic = heuristic
        self.qvac = qvac
        self.degraded = degraded


class QvacEnrichmentService:
    """Call `QvacInferencePort` for selected candidates; never a second prediction pipeline."""

    def __init__(
        self,
        port: QvacInferencePort,
        *,
        settings: Settings | None = None,
        selector: QvacCandidateSelector | None = None,
    ) -> None:
        resolved = settings or Settings.get()
        self._port = port
        self._selector = selector or QvacCandidateSelector(resolved)
        self._log = logging.getLogger(__name__)

    async def enrich(
        self,
        candidate: QvacCandidate,
        heuristic: HeuristicVerdict,
    ) -> QvacEnrichmentResult:
        if not self._selector.should_enrich(heuristic):
            return QvacEnrichmentResult(heuristic=heuristic, qvac=None, degraded=False)
        try:
            verdict = await self._port.enrich(candidate)
        except (QvacTimeoutError, QvacUnavailableError, QvacInvalidResponseError) as exc:
            self._log.warning(
                "qvac_enrichment_degraded",
                extra={"error_code": exc.code},
            )
            return QvacEnrichmentResult(heuristic=heuristic, qvac=None, degraded=True)
        return QvacEnrichmentResult(heuristic=heuristic, qvac=verdict, degraded=False)
