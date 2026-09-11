"""JSON log field policy. Changing the allowlist is a privacy review."""

from typing import Final

LOG_FIELD_ALLOWLIST: Final[frozenset[str]] = frozenset(
    {
        "timestamp",
        "level",
        "logger",
        "message",
        "event",
        "correlation_id",
        "accepted",
        "rejected",
        "status_code",
        "path",
        "method",
        "error_code",
        "source",
        "mode",
        "queue_depth",
        "result_count",
        "dependency",
        "health_status",
    }
)
LOG_FIELD_DENYLIST: Final[frozenset[str]] = frozenset(
    {
        "authorization",
        "body",
        "client_hash",
        "events",
        "password",
        "payload",
        "prompt",
        "qname",
        "qvac_prompt",
        "secret",
        "token",
        "webhook_token",
        "x_sentinel_token",
    }
)
