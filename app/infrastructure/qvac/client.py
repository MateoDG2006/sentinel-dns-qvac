"""QVAC SDK lifecycle, local completion, and bootstrap helpers.

Runtime inference never downloads models. `QvacModelBootstrap.prepare` is the
only network path and must not be called from `QvacClient`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tetherto.qvac_sdk._api import cancel, load_model, unload_model
from tetherto.qvac_sdk._completion import completion
from tetherto.qvac_sdk.client import Client, WorkerNotFoundError
from tetherto.qvac_sdk.errors import InferenceCancelledError, ModelLoadFailedError

from app.constants.qvac import (
    BOOTSTRAP_MODEL_CONSTANT,
    COMPLETION_MAX_TOKENS,
    GGUF_SUFFIX,
    HEALTH_DEPENDENCY_NAME,
    MANIFEST_FILENAME,
    MODEL_TYPE_COMPLETION,
    PROMPT_VERSION,
)
from app.core.config import Settings
from app.domain.enums import DependencyStatus
from app.domain.errors import (
    QvacInvalidResponseError,
    QvacTimeoutError,
    QvacUnavailableError,
)
from app.domain.schemas import DependencyHealth, QvacCandidate, QvacVerdict
from app.infrastructure.qvac.parser import QvacResponseParser
from app.infrastructure.qvac.prompt import QvacPrompt
from app.utils.time import UtcDateTime


class QvacModelCache:
    """Resolve a previously bootstrapped GGUF under the local cache directory."""

    def __init__(self, cache_dir: Path) -> None:
        self._cache_dir = cache_dir

    @property
    def cache_dir(self) -> Path:
        return self._cache_dir

    def resolve(self) -> Path | None:
        if not self._cache_dir.exists():
            return None
        manifest = self._read_manifest()
        if manifest is not None:
            relative = manifest.get("relative_path")
            if isinstance(relative, str) and relative:
                candidate = (self._cache_dir / relative).resolve()
                try:
                    candidate.relative_to(self._cache_dir.resolve())
                except ValueError:
                    return None
                if candidate.is_file():
                    return candidate
        found = sorted(self._cache_dir.rglob(f"*{GGUF_SUFFIX}"))
        return found[0] if found else None

    def write_manifest(self, gguf: Path) -> None:
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        relative = gguf.resolve().relative_to(self._cache_dir.resolve())
        payload = {
            "relative_path": relative.as_posix(),
            "model_type": MODEL_TYPE_COMPLETION,
            "prompt_version": PROMPT_VERSION,
            "bootstrap_model": BOOTSTRAP_MODEL_CONSTANT,
        }
        (self._cache_dir / MANIFEST_FILENAME).write_text(
            json.dumps(payload, indent=2) + "\n",
            encoding="utf-8",
        )

    def _read_manifest(self) -> dict[str, Any] | None:
        path = self._cache_dir / MANIFEST_FILENAME
        if not path.is_file():
            return None
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return loaded if isinstance(loaded, dict) else None


class QvacClient:
    """`QvacInferencePort` adapter. Uses local completion; never `classify` or downloads."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        prompt: QvacPrompt | None = None,
        parser: QvacResponseParser | None = None,
    ) -> None:
        self._settings = settings or Settings.get()
        self._prompt = prompt or QvacPrompt()
        self._parser = parser or QvacResponseParser()
        self._cache = QvacModelCache(self._settings.qvac_cache_dir)
        self._log = logging.getLogger(__name__)
        self._sdk: Client | None = None
        self._model_id: str | None = None
        self._available = False
        self._detail: str | None = "qvac has not started"
        self._semaphore = asyncio.Semaphore(self._settings.qvac_concurrency)

    @staticmethod
    def open_sdk(settings: Settings, cache_dir: str, *, log_console: bool = False) -> Client:
        return Client(
            worker_path=str(settings.qvac_worker_path) if settings.qvac_worker_path else None,
            bare_path=str(settings.qvac_bare_path) if settings.qvac_bare_path else None,
            sdk_dir=str(settings.qvac_sdk_dir.expanduser().resolve()),
            config={"cacheDirectory": cache_dir, "loggerConsoleOutput": log_console},
        )

    async def start(self) -> None:
        if self._available:
            return
        if not self._settings.qvac_enabled:
            self._available = False
            self._detail = "qvac is disabled"
            return
        gguf = self._cache.resolve()
        if gguf is None:
            self._available = False
            self._detail = (
                "local QVAC model cache is empty; run scripts/bootstrap_models.py with network"
            )
            self._log.warning("qvac_model_missing")
            return
        cache_dir = str(self._cache.cache_dir.resolve())
        os.environ["QVAC_CACHE_DIR"] = cache_dir
        try:
            self._sdk = QvacClient.open_sdk(self._settings, cache_dir)
            await self._sdk.connect()
            self._model_id = await load_model(
                self._sdk.transport,
                model_src=str(gguf),
                model_type=MODEL_TYPE_COMPLETION,
            )
        except (WorkerNotFoundError, ModelLoadFailedError, OSError, RuntimeError) as exc:
            await self._shutdown_quiet()
            self._available = False
            self._detail = "qvac worker or local model failed to start"
            self._log.warning("qvac_start_failed", extra={"code": type(exc).__name__})
            return
        self._available = True
        self._detail = None
        self._log.info("qvac_started")

    async def enrich(self, candidate: QvacCandidate) -> QvacVerdict:
        if not self._available or self._sdk is None or self._model_id is None:
            raise QvacUnavailableError(self._detail or "QVAC is unavailable")
        async with self._semaphore:
            try:
                return await asyncio.wait_for(
                    self._complete(candidate),
                    timeout=self._settings.qvac_timeout_seconds,
                )
            except TimeoutError as exc:
                raise QvacTimeoutError() from exc
            except QvacInvalidResponseError:
                raise
            except InferenceCancelledError as exc:
                raise QvacTimeoutError() from exc
            except (WorkerNotFoundError, ModelLoadFailedError, OSError, RuntimeError) as exc:
                self._available = False
                self._detail = "qvac became unavailable during enrichment"
                raise QvacUnavailableError(self._detail) from exc

    async def health(self) -> DependencyHealth:
        status = DependencyStatus.UP if self._available else DependencyStatus.DOWN
        return DependencyHealth(
            name=HEALTH_DEPENDENCY_NAME,
            status=status,
            detail=self._detail,
            checked_at=UtcDateTime.ensure(datetime.now(UTC)),
        )

    async def close(self) -> None:
        await self._shutdown_quiet()
        self._available = False
        if self._detail is None:
            self._detail = "qvac is stopped"

    async def _complete(self, candidate: QvacCandidate) -> QvacVerdict:
        assert self._sdk is not None
        assert self._model_id is not None
        run = completion(
            self._sdk.transport,
            model_id=self._model_id,
            history=self._prompt.render(candidate),
            stream=False,
            capture_thinking=False,
            generation_params={
                "temp": 0,
                "predict": COMPLETION_MAX_TOKENS,
                "reasoning_budget": 0,
            },
            response_format=self._prompt.response_format(),
        )
        try:
            final = await run.final
        except (TimeoutError, asyncio.CancelledError):
            try:
                await asyncio.shield(cancel(self._sdk.transport, request_id=run.request_id))
            except Exception:
                self._log.warning("qvac_cancel_failed")
            raise
        raw = final.content_text or final.raw_full_text or ""
        return self._parser.parse(raw, model_id=self._model_id)

    async def _shutdown_quiet(self) -> None:
        sdk = self._sdk
        model_id = self._model_id
        self._sdk = None
        self._model_id = None
        if sdk is None:
            return
        if model_id is not None:
            try:
                await unload_model(sdk.transport, model_id, clear_storage=False)
            except Exception:
                self._log.warning("qvac_unload_failed")
        try:
            await sdk.close()
        except Exception:
            self._log.warning("qvac_close_failed")


class QvacModelBootstrap:
    """Download the configured GGUF into QVAC_CACHE_DIR. Requires network."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings.get()
        self._cache = QvacModelCache(self._settings.qvac_cache_dir)

    async def prepare(self) -> Path:
        """Fetch the model into the local cache. Do not call this from runtime inference."""
        import tetherto.qvac_sdk.models as qvac_models

        model_src = getattr(qvac_models, BOOTSTRAP_MODEL_CONSTANT, None)
        if model_src is None:
            raise QvacUnavailableError(
                f"unknown bootstrap model constant {BOOTSTRAP_MODEL_CONSTANT}"
            )
        cache_dir = self._cache.cache_dir
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_path = str(cache_dir.resolve())
        os.environ["QVAC_CACHE_DIR"] = cache_path
        client = QvacClient.open_sdk(self._settings, cache_path)
        async with client:
            model_id = await load_model(client.transport, model_src=model_src)
            gguf = self._cache.resolve()
            if gguf is None:
                raise QvacUnavailableError(
                    f"bootstrap finished but no {GGUF_SUFFIX} was found under {cache_path}"
                )
            self._cache.write_manifest(gguf)
            await unload_model(client.transport, model_id, clear_storage=False)
        return gguf


class QvacLocalSmoke:
    """Optional local smoke. Skips clearly when the cache is empty. Never downloads."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings.get()

    async def run(self) -> int:
        cache = QvacModelCache(self._settings.qvac_cache_dir)
        gguf = cache.resolve()
        if gguf is None:
            print("SKIP: QVAC cache is empty. Run scripts/bootstrap_models.py with network first.")
            return 2
        client = QvacClient(settings=self._settings)
        await client.start()
        try:
            health = await client.health()
            if health.status is not DependencyStatus.UP:
                print(f"FAIL: QVAC did not become ready ({health.detail})")
                return 1
            print(f"OK: local QVAC model loaded from {gguf}")
            return 0
        finally:
            await client.close()
