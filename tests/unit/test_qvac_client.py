"""QVAC adapter cache and unavailable-model behavior. No real model download."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.constants.qvac import GGUF_SUFFIX, MANIFEST_FILENAME
from app.core.config import Settings
from app.domain.enums import DependencyStatus, ThreatType
from app.domain.errors import QvacUnavailableError
from app.domain.schemas import DnsFeatures, QvacCandidate
from app.infrastructure.qvac.client import QvacClient, QvacLocalSmoke, QvacModelCache


def _candidate() -> QvacCandidate:
    return QvacCandidate(
        event_id="11111111-1111-1111-1111-111111111111",
        qname="example.test",
        qtype="A",
        rcode="NOERROR",
        features=DnsFeatures(
            domain_entropy=1.0,
            domain_length=12,
            label_count=2,
            digit_ratio=0.0,
            vowel_ratio=0.5,
            longest_label_length=7,
            subdomain_uniqueness_1m=0.1,
            query_rate_1m=1.0,
            interval_mean_ms=None,
            interval_jitter_ms=None,
            brand_distance=None,
            suspicious_qtype=False,
            nxdomain=False,
            resolver_error=False,
        ),
        heuristic_score=0.70,
        heuristic_threat_type=ThreatType.DGA,
        heuristic_reasons=["high_entropy"],
    )


def test_cache_resolves_manifest_and_gguf(tmp_path: Path) -> None:
    gguf = tmp_path / f"local-model{GGUF_SUFFIX}"
    gguf.write_bytes(b"placeholder")
    cache = QvacModelCache(tmp_path)
    cache.write_manifest(gguf)
    assert cache.resolve() == gguf.resolve()
    assert (tmp_path / MANIFEST_FILENAME).is_file()


def test_cache_empty_directory_is_missing(tmp_path: Path) -> None:
    assert QvacModelCache(tmp_path / "missing").resolve() is None


async def test_client_missing_model_is_unavailable(tmp_path: Path) -> None:
    settings = Settings(qvac_cache_dir=tmp_path / "empty-cache")
    client = QvacClient(settings=settings)
    await client.start()
    health = await client.health()
    assert health.status is DependencyStatus.DOWN
    assert health.detail is not None
    with pytest.raises(QvacUnavailableError):
        await client.enrich(_candidate())
    await client.close()


async def test_local_smoke_skips_when_cache_empty(tmp_path: Path) -> None:
    settings = Settings(qvac_cache_dir=tmp_path / "empty-cache")
    code = await QvacLocalSmoke(settings=settings).run()
    assert code == 2
