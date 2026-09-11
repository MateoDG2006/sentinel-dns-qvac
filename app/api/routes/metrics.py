"""Prometheus metrics HTTP surface."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Response
from prometheus_client import CONTENT_TYPE_LATEST

from app.api.dependencies import ApiDependencies
from app.constants.api import METRICS_PATH
from app.observability.metrics import SentinelMetrics


class MetricsApi:
    """GET /metrics — aggregated Prometheus text without identity labels."""

    router = APIRouter(tags=["metrics"])

    @staticmethod
    async def metrics(
        collector: Annotated[SentinelMetrics, Depends(ApiDependencies.metrics)],
    ) -> Response:
        return Response(content=collector.render(), media_type=CONTENT_TYPE_LATEST)


MetricsApi.router.add_api_route(
    METRICS_PATH,
    MetricsApi.metrics,
    methods=["GET"],
    summary="Métricas Prometheus agregadas (sin qname ni client_hash)",
)
