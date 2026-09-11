"""Liveness and readiness HTTP surface."""

from __future__ import annotations

from typing import Annotated, cast

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from app.api.dependencies import ApiDependencies
from app.constants.api import HEALTH_LIVE_PATH, HEALTH_READY_PATH
from app.core.lifecycle import AppLifecycle
from app.domain.enums import ServiceState
from app.observability.health import HealthProbe


class HealthApi:
    """GET /health/live and GET /health/ready."""

    router = APIRouter(tags=["health"])

    @staticmethod
    async def live(
        probe: Annotated[HealthProbe, Depends(ApiDependencies.health)],
    ) -> dict[str, str]:
        return probe.liveness()

    @staticmethod
    async def ready(
        request: Request,
        probe: Annotated[HealthProbe, Depends(ApiDependencies.health)],
    ) -> JSONResponse:
        service_state = cast(
            ServiceState,
            getattr(request.app.state, "service_state", ServiceState.READY),
        )
        status_code, body = await probe.readiness(
            service_state=service_state,
            qvac=getattr(request.app.state, "qvac_client", None),
            kafka=getattr(request.app.state, "kafka_consumer", None),
            outbox=getattr(request.app.state, "outbox", None),
            kafka_enabled=AppLifecycle.kafka_consumer_enabled(),
        )
        return JSONResponse(status_code=status_code, content=body)


HealthApi.router.add_api_route(
    HEALTH_LIVE_PATH,
    HealthApi.live,
    methods=["GET"],
    summary="Liveness: el proceso y el event loop responden",
)
HealthApi.router.add_api_route(
    HEALTH_READY_PATH,
    HealthApi.ready,
    methods=["GET"],
    summary="Readiness: config y Kafka listos; QVAC degradado no fuerza 503",
)
