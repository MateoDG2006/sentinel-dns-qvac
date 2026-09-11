"""Strict JSON parser for local QVAC completion output."""

from __future__ import annotations

from pydantic import Field, ValidationError

from app.domain.enums import ThreatType
from app.domain.errors import QvacInvalidResponseError
from app.domain.schemas import FrozenModel, QvacVerdict
from app.utils.json import JsonObject


class QvacModelPayload(FrozenModel):
    """Fields the local model is allowed to emit. Extra keys are rejected."""

    threat_type: ThreatType
    score: float = Field(ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)


class QvacResponseParser:
    """Validate QVAC text as a QvacVerdict. Repair retries belong to later consumers."""

    def parse(self, raw: str, *, model_id: str) -> QvacVerdict:
        try:
            payload = JsonObject.loads_object(raw)
        except ValueError as exc:
            message = str(exc)
            if "truncated" in message:
                raise QvacInvalidResponseError("QVAC response JSON is truncated") from exc
            raise QvacInvalidResponseError("QVAC response was not valid JSON") from exc
        try:
            parsed = QvacModelPayload.model_validate(payload)
        except ValidationError as exc:
            raise QvacInvalidResponseError(self._validation_message(exc)) from exc
        return QvacVerdict(
            threat_type=parsed.threat_type,
            score=parsed.score,
            reasons=parsed.reasons,
            model_id=model_id,
        )

    @staticmethod
    def _validation_message(exc: ValidationError) -> str:
        for error in exc.errors():
            error_type = str(error.get("type", ""))
            location = error.get("loc", ())
            if error_type == "extra_forbidden":
                return "QVAC JSON contains extra fields"
            if "score" in location:
                return "QVAC score is out of range"
        return "QVAC JSON failed schema validation"
