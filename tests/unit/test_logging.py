"""JSON logging allowlist and webhook token comparison tests."""

from __future__ import annotations

import json
import logging

from app.core.logging import JsonLogFormatter
from app.core.security import WebhookToken


def test_webhook_token_uses_constant_time_compare() -> None:
    assert WebhookToken.matches(provided="same-token", expected="same-token")
    assert not WebhookToken.matches(provided="same-token", expected="other-token")


def test_json_formatter_keeps_allowlist_and_drops_secrets() -> None:
    record = logging.LogRecord(
        name="app.api.predictions",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="predictions_accepted",
        args=(),
        exc_info=None,
    )
    record.correlation_id = "cid-1"
    record.accepted = 1
    record.qname = "secret.example"
    record.token = "super-secret-token"
    record.prompt = "do not log this prompt"
    record.client_hash = "abc123"
    formatted = JsonLogFormatter().format(record)
    payload = json.loads(formatted)
    assert payload["message"] == "predictions_accepted"
    assert payload["correlation_id"] == "cid-1"
    assert payload["accepted"] == 1
    assert "qname" not in payload
    assert "token" not in payload
    assert "prompt" not in payload
    assert "client_hash" not in payload
    assert "super-secret-token" not in formatted
    assert "do not log this prompt" not in formatted
