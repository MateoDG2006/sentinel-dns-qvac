"""WazuhTls: missing CA must not crash process startup."""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest

from app.core.config import WazuhSettings
from app.infrastructure.wazuh.tls import WazuhTls


def test_verify_without_ca_uses_flag() -> None:
    assert WazuhTls.verify(WazuhSettings()) is True
    assert WazuhTls.verify(WazuhSettings(verify_tls=False)) is False


def test_verify_missing_ca_file_falls_back(tmp_path: Path) -> None:
    settings = WazuhSettings(ca_path=tmp_path / "missing.pem", verify_tls=True)
    assert WazuhTls.verify(settings) is True


def test_verify_directory_instead_of_file_falls_back(tmp_path: Path) -> None:
    settings = WazuhSettings(ca_path=tmp_path, verify_tls=True)
    assert WazuhTls.verify(settings) is True


def test_verify_existing_ca_skips_hostname(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pem = tmp_path / "root-ca.pem"
    pem.write_text("not-a-real-pem\n", encoding="ascii")
    captured: ssl.SSLContext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    def _fake_context(**_kwargs: object) -> ssl.SSLContext:
        return captured

    monkeypatch.setattr("app.infrastructure.wazuh.tls.ssl.create_default_context", _fake_context)
    result = WazuhTls.verify(WazuhSettings(ca_path=pem, verify_tls=True))
    assert result is captured
    assert captured.check_hostname is False
