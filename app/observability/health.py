"""Composite liveness and readiness from live adapters.

QVAC down stays HTTP 200 while heuristic fallback is active. Kafka down
makes the process not-ready. Outbox may be degraded (volatile) without 503.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, Protocol

from app.constants.health import (
    CONFIG_DEPENDENCY_NAME,
    KAFKA_DEPENDENCY_NAME,
    KAFKA_DISABLED_DETAIL,
    KAFKA_UNAVAILABLE_DETAIL,
    OUTBOX_DEPENDENCY_NAME,
    OUTBOX_VOLATILE_DETAIL,
    QVAC_FALLBACK_DETAIL,
)
from app.constants.qvac import HEALTH_DEPENDENCY_NAME as QVAC_DEPENDENCY_NAME
from app.core.config import Settings
from app.domain.enums import DependencyStatus, ServiceState
from app.domain.schemas import DependencyHealth
from app.utils.time import UtcDateTime


class HealthComponent(Protocol):
    async def health(self) -> DependencyHealth: ...


class HealthProbe:
    """Process liveness and dependency checks for /health/ready."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def liveness(self) -> dict[str, str]:
        loop = asyncio.get_running_loop()
        if loop.is_closed():
            raise RuntimeError("event loop is closed")
        return {"status": "live"}

    async def readiness(
        self,
        *,
        service_state: ServiceState,
        qvac: HealthComponent | None = None,
        kafka: HealthComponent | None = None,
        outbox: HealthComponent | None = None,
        kafka_enabled: bool = False,
    ) -> tuple[int, dict[str, Any]]:
        checked_at = UtcDateTime.ensure(datetime.now(UTC))
        config_status = self._config_status()
        kafka_health = await self._kafka_health(kafka, enabled=kafka_enabled, checked_at=checked_at)
        qvac_health = self._qvac_for_ready(
            await self._read(
                qvac,
                name=QVAC_DEPENDENCY_NAME,
                status=DependencyStatus.DEGRADED,
                detail=QVAC_FALLBACK_DETAIL,
                checked_at=checked_at,
            )
        )
        outbox_health = await self._read(
            outbox,
            name=OUTBOX_DEPENDENCY_NAME,
            status=DependencyStatus.DEGRADED,
            detail=OUTBOX_VOLATILE_DETAIL,
            checked_at=checked_at,
        )
        dependencies = [
            DependencyHealth(
                name=CONFIG_DEPENDENCY_NAME,
                status=config_status,
                detail=None,
                checked_at=checked_at,
            ),
            kafka_health,
            qvac_health,
            outbox_health,
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
        if kafka_health.status is DependencyStatus.DOWN:
            payload["status"] = "not_ready"
            return 503, payload
        return 200, payload

    async def _kafka_health(
        self,
        kafka: HealthComponent | None,
        *,
        enabled: bool,
        checked_at: datetime,
    ) -> DependencyHealth:
        if kafka is not None:
            return await self._read(
                kafka,
                name=KAFKA_DEPENDENCY_NAME,
                status=DependencyStatus.DOWN,
                detail=KAFKA_UNAVAILABLE_DETAIL,
                checked_at=checked_at,
            )
        if enabled:
            return DependencyHealth(
                name=KAFKA_DEPENDENCY_NAME,
                status=DependencyStatus.DOWN,
                detail=KAFKA_UNAVAILABLE_DETAIL,
                checked_at=checked_at,
            )
        return DependencyHealth(
            name=KAFKA_DEPENDENCY_NAME,
            status=DependencyStatus.DEGRADED,
            detail=KAFKA_DISABLED_DETAIL,
            checked_at=checked_at,
        )

    @staticmethod
    def _qvac_for_ready(health: DependencyHealth) -> DependencyHealth:
        if health.status is DependencyStatus.UP:
            return health
        return DependencyHealth(
            name=health.name,
            status=DependencyStatus.DEGRADED,
            detail=health.detail or QVAC_FALLBACK_DETAIL,
            checked_at=health.checked_at,
        )

    @staticmethod
    async def _read(
        component: object | None,
        *,
        name: str,
        status: DependencyStatus,
        detail: str,
        checked_at: datetime,
    ) -> DependencyHealth:
        if component is None:
            return DependencyHealth(
                name=name,
                status=status,
                detail=detail,
                checked_at=checked_at,
            )
        health_fn = getattr(component, "health", None)
        if callable(health_fn):
            result = await health_fn()
            if isinstance(result, DependencyHealth):
                return result
        return DependencyHealth(
            name=name,
            status=status,
            detail=detail,
            checked_at=checked_at,
        )

    def _config_status(self) -> DependencyStatus:
        _ = self._settings.app_host
        return DependencyStatus.UP
