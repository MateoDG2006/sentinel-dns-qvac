"""Webhook token comparison. Never log the secret value."""

from __future__ import annotations

import hmac


class WebhookToken:
    """Constant-time comparison for the local webhook shared secret."""

    @staticmethod
    def matches(*, provided: str, expected: str) -> bool:
        return hmac.compare_digest(provided, expected)
