"""Process start/stop: shared PredictionService, QVAC adapter, Kafka consumer."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import cast

from fastapi import FastAPI

from app.constants.prediction import KAFKA_CONSUMER_ENV
from app.core.config import Settings
from app.domain.enums import DetectorRuntime, EventSource, PredictionMode, ServiceState
from app.domain.ports import BatchHandler, OutboxPort
from app.domain.schemas import NormalizedDnsEvent
from app.infrastructure.kafka.consumer import KafkaDnsConsumer
from app.infrastructure.qvac.client import QvacClient
from app.observability.metrics import SentinelMetrics
from app.services.feature_extraction import FeatureExtractor
from app.services.heuristics import HeuristicThreatDetector
from app.services.prediction import PredictionService, QoeSink, VolatileOutbox
from app.services.qvac_enrichment import QvacEnrichmentService


class AppLifecycle:
    """Wire the shared prediction pipeline and optionally start the Kafka consumer."""

    @staticmethod
    def kafka_consumer_enabled() -> bool:
        flag = os.environ.get(KAFKA_CONSUMER_ENV, "1").strip().lower()
        return flag not in {"0", "false", "no", "off"}

    @staticmethod
    @asynccontextmanager
    async def run(app: FastAPI, settings: Settings) -> AsyncIterator[None]:
        metrics: SentinelMetrics = app.state.metrics
        app.state.service_state = ServiceState.STARTING
        qvac = QvacClient(settings=settings)
        await qvac.start()
        health = await qvac.health()
        metrics.set_qvac_available(health.status.value == "up")
        extractor = FeatureExtractor(settings=settings)
        detector = HeuristicThreatDetector(settings=settings)
        enrichment = QvacEnrichmentService(qvac, settings=settings)
        existing = getattr(app.state, "prediction_service", None)
        queue = existing.queue if isinstance(existing, PredictionService) else None
        outbox = AppLifecycle._resolve_outbox(app)
        qoe = AppLifecycle._resolve_qoe(app)
        service = PredictionService(
            settings,
            extractor=extractor,
            detector=detector,
            enrichment=enrichment,
            outbox=outbox,
            qoe=qoe,
            queue=queue,
        )
        app.state.prediction_service = service
        app.state.qvac_client = qvac
        app.state.outbox = outbox
        consumer: KafkaDnsConsumer | None = None
        consumer_task: asyncio.Task[None] | None = None
        if AppLifecycle.kafka_consumer_enabled():
            consumer = KafkaDnsConsumer(settings, metrics=metrics)
            app.state.kafka_consumer = consumer
            handler = AppLifecycle._kafka_handler(service, metrics)
            consumer_task = asyncio.create_task(
                AppLifecycle._run_consumer(consumer, handler, metrics),
                name="sentinel-kafka-consumer",
            )
        app.state.service_state = ServiceState.READY
        try:
            yield
        finally:
            app.state.service_state = ServiceState.STOPPING
            if consumer is not None:
                await consumer.stop()
            if consumer_task is not None:
                consumer_task.cancel()
                try:
                    await consumer_task
                except (asyncio.CancelledError, Exception):
                    pass
            await qvac.close()
            app.state.service_state = ServiceState.STOPPED

    @staticmethod
    def _resolve_outbox(app: FastAPI) -> OutboxPort:
        existing = getattr(app.state, "outbox", None)
        if existing is not None and callable(getattr(existing, "enqueue", None)):
            return cast(OutboxPort, existing)
        return VolatileOutbox()

    @staticmethod
    def _resolve_qoe(app: FastAPI) -> QoeSink | None:
        existing = getattr(app.state, "qoe", None)
        if existing is not None and callable(getattr(existing, "observe", None)):
            return cast(QoeSink, existing)
        return None

    @staticmethod
    def _kafka_handler(service: PredictionService, metrics: SentinelMetrics) -> BatchHandler:
        async def handle(events: list[NormalizedDnsEvent]) -> None:
            results = await service.process_batch(events, EventSource.KAFKA)
            metrics.increment_events(
                source=EventSource.KAFKA.value,
                status="accepted",
                amount=len(results),
            )
            for item in results:
                runtime = (
                    DetectorRuntime.HEURISTIC_FALLBACK.value
                    if item.mode is PredictionMode.HEURISTIC_FALLBACK
                    else DetectorRuntime.QVAC_LOCAL.value
                )
                metrics.increment_prediction(
                    threat_type=item.prediction.threat_type.value,
                    severity=item.prediction.severity.value,
                    runtime=runtime,
                )

        return handle

    @staticmethod
    async def _run_consumer(
        consumer: KafkaDnsConsumer,
        handler: BatchHandler,
        metrics: SentinelMetrics,
    ) -> None:
        try:
            await consumer.run(handler)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            consumer.mark_unavailable(type(exc).__name__)
            metrics.set_kafka_consumer_lag(-1)
