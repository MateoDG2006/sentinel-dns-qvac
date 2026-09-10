"""Composite liveness and readiness. Missing Kafka/QVAC must not force 503."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from app.core.config import Settings
from app.domain.enums import DependencyStatus, ServiceState
from app.domain.schemas import DependencyHealth


class HealthProbe:
    """Process liveness and degraded-but-ready checks for stubbed dependencies."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def liveness(self) -> dict[str, str]:
        loop = asyncio.get_running_loop()
        if loop.is_closed():
            raise RuntimeError("event loop is closed")
        return {"status": "live"}

    def readiness(self, *, service_state: ServiceState) -> tuple[int, dict[str, Any]]:
        checked_at = datetime.now(UTC)
        config_status = self._config_status()
        dependencies = [
            DependencyHealth(
                name="config",
                status=config_status,
                detail=None,
                checked_at=checked_at,
            ),
            DependencyHealth(
                name="kafka",
                status=DependencyStatus.DEGRADED,
                detail="adapter_not_implemented",
                checked_at=checked_at,
            ),
            DependencyHealth(
                name="qvac",
                status=DependencyStatus.DEGRADED,
                detail="adapter_not_implemented_heuristic_fallback_active",
                checked_at=checked_at,
            ),
            DependencyHealth(
                name="outbox",
                status=DependencyStatus.DEGRADED,
                detail="adapter_not_implemented",
                checked_at=checked_at,
            ),
        ]
        payload: dict[str, Any] = {
            "status": "ready",
            "service_state": service_state.value,
            "dependencies": [item.model_dump(mode="json") for item in dependencies],
        }
        if service_state in {ServiceState.STOPPING, ServiceState.STOPPED}:
            payload["status"] = "not_ready"
            return 503, payload
        if config_status is DependencyStatus.DOWN:
            payload["status"] = "not_ready"
            return 503, payload
        return 200, payload

    def _config_status(self) -> DependencyStatus:
        _ = self._settings.app_host
        return DependencyStatus.UP
