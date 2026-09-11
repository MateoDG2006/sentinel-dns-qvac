"""Process start/stop hooks. Kafka and QVAC stay unstarted until later tasks."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import Settings
from app.domain.enums import ServiceState
from app.observability.metrics import SentinelMetrics


class AppLifecycle:
    """Bind in-process collaborators without starting Kafka or QVAC workers."""

    @staticmethod
    @asynccontextmanager
    async def run(app: FastAPI, settings: Settings) -> AsyncIterator[None]:
        _ = settings
        app.state.service_state = ServiceState.STARTING
        metrics: SentinelMetrics = app.state.metrics
        metrics.set_qvac_available(False)
        metrics.set_kafka_consumer_lag(0)
        metrics.set_outbox_pending(0)
        app.state.service_state = ServiceState.READY
        try:
            yield
        finally:
            app.state.service_state = ServiceState.STOPPING
            app.state.service_state = ServiceState.STOPPED
