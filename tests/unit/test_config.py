"""Unit tests for typed Settings and no-egress defaults."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.constants.clickhouse import QOE_TABLE
from app.constants.kafka import TOPIC_DLQ, TOPIC_GROUNDTRUTH, TOPIC_NORMALIZED
from app.core.config import Settings
from app.domain.enums import RuntimeProfile


def test_default_settings_are_local_and_offline() -> None:
    settings = Settings(_env_file=None)
    assert settings.app_host == "127.0.0.1"
    assert settings.app_port == 8000
    assert settings.no_egress is True
    assert settings.require_synthetic is True
    assert settings.runtime_profile is RuntimeProfile.HACKATHON
    assert settings.kafka.topic_normalized == TOPIC_NORMALIZED
    assert settings.kafka.topic_dlq == TOPIC_DLQ
    assert settings.kafka.topic_groundtruth == TOPIC_GROUNDTRUTH
    assert settings.clickhouse.qoe_table == QOE_TABLE
    assert settings.qvac_sdk_dir == Path("node_modules") / "@qvac" / "sdk"
    assert settings.qvac_timeout_seconds == 1.5
    assert settings.qvac_concurrency == 1
    assert settings.wazuh.verify_tls is True
    assert settings.wazuh.batch_max == 100


def test_no_egress_rejects_public_endpoints() -> None:
    with pytest.raises(ValidationError):
        Settings(wazuh={"base_url": "https://events.wazuh.example:55000"})
    with pytest.raises(ValidationError):
        Settings(kafka={"bootstrap_servers": "kafka.apache.org:9092"})
    with pytest.raises(ValidationError):
        Settings(clickhouse={"host": "8.8.8.8"})


def test_insecure_tls_requires_local_insecure_profile() -> None:
    with pytest.raises(ValidationError):
        Settings(wazuh={"verify_tls": False})
    settings = Settings(
        runtime_profile=RuntimeProfile.LOCAL_INSECURE,
        wazuh={"verify_tls": False, "base_url": "https://127.0.0.1:55000"},
    )
    assert settings.wazuh.verify_tls is False


def test_webhook_token_prefers_secret_file(tmp_path: Path) -> None:
    token_file = tmp_path / "webhook_token"
    token_file.write_text("file-token\n", encoding="utf-8")
    settings = Settings(webhook_token="env-token", webhook_token_file=token_file)
    assert settings.resolved_webhook_token() == "file-token"


def test_qvac_cache_dir_honors_spec_env_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QVAC_CACHE_DIR", "data/custom-qvac")
    settings = Settings()
    assert settings.qvac_cache_dir == Path("data/custom-qvac")


def test_qvac_sdk_dir_honors_spec_env_name(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("QVAC_SDK_DIR", str(tmp_path / "qvac-sdk"))
    settings = Settings()
    assert settings.qvac_sdk_dir == tmp_path / "qvac-sdk"


def test_settings_get_returns_cached_instance() -> None:
    Settings.clear_cache()
    first = Settings.get()
    second = Settings.get()
    assert first is second
    Settings.clear_cache()
