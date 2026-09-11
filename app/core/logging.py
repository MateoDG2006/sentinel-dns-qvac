"""JSON logging with an allowlist. Secrets, prompts, and DNS bodies stay out."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from app.constants.logging import LOG_FIELD_ALLOWLIST, LOG_FIELD_DENYLIST
from app.core.config import Settings


class JsonLogFormatter(logging.Formatter):
    """Serialize only allowlisted fields to a single JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key in LOG_FIELD_DENYLIST:
                continue
            if key in payload:
                continue
            if key in LOG_FIELD_ALLOWLIST:
                payload[key] = value
        return json.dumps(payload, default=str)


class JsonLogging:
    """Process-wide JSON logging for the application logger namespace."""

    @staticmethod
    def configure(settings: Settings) -> None:
        _ = settings
        handler = logging.StreamHandler()
        handler.setFormatter(JsonLogFormatter())
        logger = logging.getLogger("app")
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
