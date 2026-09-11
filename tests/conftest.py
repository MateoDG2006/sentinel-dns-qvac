"""Deterministic test defaults. Kafka consumer stays off so TestClient skips C1's broker."""

from __future__ import annotations

import random

import pytest

from app.core.config import Settings


@pytest.fixture(autouse=True)
def _fixed_seed() -> None:
    random.seed(42)


@pytest.fixture(autouse=True)
def _unit_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    monkeypatch.setenv("SENTINEL_ENABLE_KAFKA_CONSUMER", "0")
    cache = tmp_path_factory.mktemp("qvac-cache")
    monkeypatch.setenv("QVAC_CACHE_DIR", str(cache))
    Settings.clear_cache()
    yield
    Settings.clear_cache()
