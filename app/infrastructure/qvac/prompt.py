"""Versioned local completion prompt for DNS threat enrichment."""

from __future__ import annotations

import json
from typing import Any

from app.constants.qvac import PROMPT_VERSION, RESPONSE_SCHEMA_NAME
from app.domain.enums import ThreatType
from app.domain.schemas import QvacCandidate


class QvacPrompt:
    """Build a compact, local-only chat history. Never log the rendered prompt."""

    _SYSTEM = (
        "You are a local DNS threat analyst. Reply with a single JSON object and no "
        "other text. Allowed threat_type values: dga, typosquatting, dns_tunneling, "
        "beaconing, none. score must be a number between 0 and 1 inclusive. reasons "
        f"must be an array of short machine-stable tokens. Prompt version {PROMPT_VERSION}."
    )

    def render(self, candidate: QvacCandidate) -> list[dict[str, str]]:
        user_payload = {
            "prompt_version": PROMPT_VERSION,
            "qtype": candidate.qtype,
            "rcode": candidate.rcode,
            "qname": candidate.qname,
            "heuristic_threat_type": candidate.heuristic_threat_type.value,
            "heuristic_score": candidate.heuristic_score,
            "heuristic_reasons": candidate.heuristic_reasons,
            "features": candidate.features.model_dump(mode="json"),
        }
        return [
            {"role": "system", "content": self._SYSTEM},
            {"role": "user", "content": json.dumps(user_payload, separators=(",", ":"))},
        ]

    @staticmethod
    def response_format() -> dict[str, Any]:
        threat_values = [member.value for member in ThreatType]
        return {
            "type": "json_schema",
            "json_schema": {
                "name": RESPONSE_SCHEMA_NAME,
                "strict": True,
                "schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["threat_type", "score", "reasons"],
                    "properties": {
                        "threat_type": {"type": "string", "enum": threat_values},
                        "score": {"type": "number", "minimum": 0, "maximum": 1},
                        "reasons": {"type": "array", "items": {"type": "string"}},
                    },
                },
            },
        }
