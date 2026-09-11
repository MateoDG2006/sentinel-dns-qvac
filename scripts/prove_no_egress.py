"""Prove Sentinel-DNS's real inference path needs no Internet access (gate G5, WBS B4).

This does NOT mock or simulate anything. It runs a real QVAC completion
against a locally cached model while a deliberate outbound connection
attempt is verified to fail, then writes a timestamped, hashable evidence
artifact.

REQUIRED before running this with egress actually blocked:
    1. Bootstrap the model once, WITH network access:
           uv run python scripts/bootstrap_models.py
       (QvacModelBootstrap.prepare() is the only code path in this codebase
       that touches the network -- this script never imports or calls it.)
    2. Actually cut network access for the duration of this run. In order
       of how convincing the evidence is:
         a. Disconnect/disable the machine's network adapter entirely
            (simplest, fully genuine, what this run's evidence used).
         b. `docker run --network none` with this repo + a bootstrapped
            /data/qvac volume mounted in (reproducible; needs a working
            Dockerfile, which doesn't exist yet -- C4's territory).
         c. Kubernetes NetworkPolicy default-deny egress (the real
            deployment target per PLAN_IMPLEMENTACION_SENTINEL_DNS.md sec.13).

    IMPORTANT LIMITATION, stated plainly: inference runs through a Node.js
    worker subprocess (tetherto_qvac_sdk's Client/transport), not pure
    Python sockets. This script's own connection probe only proves ITS
    process can't reach the internet -- it does not independently verify
    the Node worker's own socket behavior. Option (a) or (b) above (a real
    OS/container-level block) covers the worker process too; a
    Python-level-only block would not. This script assumes you used (a),
    (b), or (c), not a Python-only mock.

Exit codes: 0 = proof complete, both conditions verified for real. Non-zero
= something failed; the printed message says what. Never prints success
without both a real inference result AND a real blocked-connection result.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from app.core.config import Settings
from app.domain.enums import ThreatType
from app.domain.schemas import DnsFeatures, QvacCandidate
from app.infrastructure.qvac.client import QvacClient, QvacModelCache

EVIDENCE_DIR = Path("docs/evidence")
PROOF_INFERENCE_TIMEOUT_SECONDS = 120.0
"""Generous timeout for THIS proof script only -- a cold CPU model load plus
a first real completion can take far longer than the production
qvac_timeout_seconds default (1.5s, tuned for a warm pipeline). We override
via Settings.model_copy() below rather than editing app/core/config.py or
app/constants/qvac.py, since those are shared A-track files outside B4's
scope and this timeout is specific to proving the path works at all, not
to production latency behavior."""
PUBLIC_PROBE_HOST = "8.8.8.8"  # Google public DNS -- stable, well-known, not our infra
PUBLIC_PROBE_PORT = 53
PUBLIC_PROBE_TIMEOUT_SECONDS = 3.0


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _redacted_config_snapshot(settings: Settings) -> dict[str, object]:
    """Hashable snapshot of what matters for this proof. No secrets included."""
    return {
        "no_egress": settings.no_egress,
        "runtime_profile": settings.runtime_profile.value,
        "qvac_enabled": settings.qvac_enabled,
        "qvac_cache_dir": str(settings.qvac_cache_dir),
        "qvac_timeout_seconds": settings.qvac_timeout_seconds,
        "kafka_bootstrap_servers": settings.kafka.bootstrap_servers,
        "wazuh_base_url": settings.wazuh.base_url,
        "clickhouse_host": settings.clickhouse.host,
    }


def _attempt_public_connection() -> tuple[bool, str]:
    """Try a real outbound connection. Returns (blocked, detail).

    blocked=True (connection FAILED) is the desired/expected result. If the
    connection actually succeeds, egress is not really blocked right now --
    treated as a hard failure of the whole proof, not a partial pass.
    """
    try:
        with socket.create_connection(
            (PUBLIC_PROBE_HOST, PUBLIC_PROBE_PORT), timeout=PUBLIC_PROBE_TIMEOUT_SECONDS
        ):
            pass
    except OSError as exc:
        return True, f"{type(exc).__name__}: {exc}"
    return False, "connection unexpectedly SUCCEEDED -- egress is not actually blocked"


def _sample_candidate() -> QvacCandidate:
    """A representative ambiguous-score DGA-shaped candidate.

    Illustrative values -- this proves the inference *path* works with no
    egress, not detector accuracy.
    """
    return QvacCandidate(
        event_id=uuid4(),
        qname="xj3k9fqm2z.example.net",
        qtype="A",
        rcode="NOERROR",
        features=DnsFeatures(
            domain_entropy=3.8,
            domain_length=22,
            label_count=2,
            digit_ratio=0.3,
            vowel_ratio=0.15,
            longest_label_length=10,
            subdomain_uniqueness_1m=0.9,
            query_rate_1m=1.0,
            interval_mean_ms=None,
            interval_jitter_ms=None,
            brand_distance=None,
            suspicious_qtype=False,
            nxdomain=False,
            resolver_error=False,
        ),
        heuristic_score=0.62,
        heuristic_threat_type=ThreatType.DGA,
        heuristic_reasons=["high_entropy", "atypical_length"],
    )


async def _run_real_inference(settings: Settings) -> tuple[bool, dict[str, object]]:
    """Actually start QVAC and run one real completion. No mocks."""
    proof_settings = settings.model_copy(
        update={"qvac_timeout_seconds": PROOF_INFERENCE_TIMEOUT_SECONDS}
    )
    client = QvacClient(settings=proof_settings)
    await client.start()
    try:
        health = await client.health()
        if health.status.value != "up":
            return False, {"error": f"QVAC did not become available: {health.detail}"}
        verdict = await client.enrich(_sample_candidate())
        return True, {
            "threat_type": verdict.threat_type.value,
            "score": verdict.score,
            "model_id": verdict.model_id,
            "reasons": verdict.reasons,
        }
    finally:
        await client.close()


def main() -> int:
    settings = Settings.get()

    print("=== Sentinel-DNS no-egress proof (WBS B4) ===")
    print(f"runtime_profile={settings.runtime_profile.value} no_egress={settings.no_egress}")

    cache = QvacModelCache(settings.qvac_cache_dir)
    gguf = cache.resolve()
    if gguf is None:
        print(
            "FAIL: no local model found under "
            f"{settings.qvac_cache_dir}. Run 'uv run python scripts/bootstrap_models.py' "
            "WITH network access first -- this script deliberately never does that itself."
        )
        return 2
    model_hash = _sha256_file(gguf)
    print(f"Local model: {gguf} (sha256 {model_hash[:16]}...)")

    print(
        f"Attempting a real outbound connection to {PUBLIC_PROBE_HOST}:{PUBLIC_PROBE_PORT} "
        "(expected to FAIL if egress is actually blocked)..."
    )
    blocked, probe_detail = _attempt_public_connection()
    print(f"  -> {probe_detail}")
    if not blocked:
        print(
            "FAIL: outbound connection succeeded. Egress is not actually blocked right now "
            "-- disconnect your network adapter, or run this inside `docker run --network "
            "none`, then retry. A pass here would prove nothing."
        )
        return 3

    print("Running real local inference (QvacClient.start + enrich)...")
    inference_ok, inference_result = asyncio.run(_run_real_inference(settings))
    if not inference_ok:
        print(f"FAIL: {inference_result.get('error')}")
        return 4
    print(f"  -> {inference_result}")

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    evidence_path = EVIDENCE_DIR / f"no_egress_{timestamp}.txt"
    config_snapshot = _redacted_config_snapshot(settings)
    config_hash = hashlib.sha256(
        json.dumps(config_snapshot, sort_keys=True).encode("utf-8")
    ).hexdigest()

    evidence = {
        "timestamp_utc": timestamp,
        "model_path": str(gguf),
        "model_sha256": model_hash,
        "config_snapshot": config_snapshot,
        "config_sha256": config_hash,
        "public_connection_probe": {
            "target": f"{PUBLIC_PROBE_HOST}:{PUBLIC_PROBE_PORT}",
            "blocked": blocked,
            "detail": probe_detail,
        },
        "inference_result": inference_result,
        "verdict": (
            "PASS -- real local inference succeeded while a real public "
            "connection attempt failed"
        ),
    }
    evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(f"\nPASS. Evidence written to {evidence_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())