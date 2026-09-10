"""Strict JSON object decoding used by the QVAC response parser."""

from __future__ import annotations

import json
from typing import Any


class JsonObject:
    """Parse a single JSON object and reject truncated or trailing payloads."""

    @staticmethod
    def loads_object(raw: str) -> dict[str, Any]:
        if not raw or not raw.strip():
            raise ValueError("JSON payload is empty")
        text = JsonObject._strip_fences(raw.strip())
        try:
            value, index = json.JSONDecoder().raw_decode(text)
        except json.JSONDecodeError as exc:
            if text.startswith("{") and text.count("{") > text.count("}"):
                raise ValueError("truncated JSON object") from exc
            raise ValueError("invalid JSON") from exc
        if text[index:].strip():
            raise ValueError("trailing content after JSON object")
        if not isinstance(value, dict):
            raise ValueError("JSON payload must be an object")
        return value

    @staticmethod
    def _strip_fences(text: str) -> str:
        if not text.startswith("```"):
            return text
        lines = text.splitlines()
        if len(lines) < 2 or lines[-1].strip() != "```":
            return text
        body = lines[1:-1]
        if body and body[0].strip().lower() in {"json", "jsonc"}:
            body = body[1:]
        return "\n".join(body).strip()
