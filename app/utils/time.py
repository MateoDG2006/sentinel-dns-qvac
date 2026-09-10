"""UTC timestamp helpers shared by domain contracts."""

from __future__ import annotations

from datetime import UTC, datetime


class UtcDateTime:
    """Require timezone-aware values and normalize them to UTC."""

    @staticmethod
    def ensure(value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware UTC")
        return value.astimezone(UTC)
