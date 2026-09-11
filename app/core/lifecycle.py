"""Process start/stop: shared PredictionService, QVAC, outbox, Wazuh, QoE, Kafka."""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import cast

import httpx
from fastapi import FastAPI

from app.constants.clickhouse import QOE_FLUSH_POLL_SECONDS
from app.constants.prediction import (
    BACKGROUND_POLL_SECONDS,
    KAFKA_CONSUMER_ENV,
    QOE_FLUSH_ENV,
    WAZUH_DISPATCHER_ENV,
)
from app.core.config import Settings, WazuhSettings
from app.domain.enums import DetectorRuntime, EventSource, PredictionMode, ServiceState
from app.domain.ports import BatchHandler, OutboxPort
from app.domain.schemas import NormalizedDnsEvent
from app.infrastructure.clickhouse.client import ClickHouseClient, ClickHouseSettingsLike
from app.infrastructure.clickhouse.repository import ClickHouseQoeRepository
from app.infrastructure.kafka.consumer import KafkaDnsConsumer
from app.infrastructure.persistence.sqlite import SqliteOutbox
from app.infrastructure.qvac.client import QvacClient
from app.infrastructure.wazuh.client import WazuhClient
from app.infrastructure.wazuh.dispatcher import WazuhOutboxDispatcher
from app.observability.metrics import SentinelMetrics
from app.services.feature_extraction import FeatureExtractor
from app.services.heuristics import HeuristicThreatDetector
from app.services.prediction import PredictionService, QoeSink
from app.services.qoe import DnsQoeSink, QoeAggregator, QoeWindowResult, load_thresholds
from app.services.qvac_enrichment import QvacEnrichmentService


class QoeFlushWorker:
    """Flush closed QoE windows without dropping them if ClickHouse rejects the write."""

    def __init__(
        self,
        aggregator: QoeAggregator,
        repository: ClickHouseQoeRepository,
        metrics: SentinelMetrics,
    ) -> None:
        self._aggregator = aggregator
        self._repository = repository
        self._metrics = metrics
        self._pending: list[QoeWindowResult] = []

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    async def run(self) -> None:
        while True:
            await asyncio.sleep(QOE_FLUSH_POLL_SECONDS)
            await self.tick(datetime.now(UTC))

    async def tick(self, now: datetime) -> None:
        log = logging.getLogger("app.core.lifecycle")
        try:
            state = await self._repository.health()
            if not state.healthy:
                self._metrics.increment_qoe_flush(status="unavailable")
                return
            self._pending.extend(self._aggregator.collect_due_windows(now))
            if not self._pending:
                return
            await self._repository.upsert_windows(self._pending)
            self._metrics.increment_qoe_flush(status="ok", amount=len(self._pending))
            self._pending.clear()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning(
                "qoe flush failed",
                extra={"event": "qoe_flush_failed", "error_code": type(exc).__name__},
            )
            self._metrics.increment_qoe_flush(status="error")


class AppLifecycle:
    """Wire the shared prediction pipeline and optional Kafka / Wazuh / QoE workers."""

    @staticmethod
    def kafka_consumer_enabled() -> bool:
        return AppLifecycle._env_enabled(KAFKA_CONSUMER_ENV)

    @staticmethod
    def _env_enabled(name: str, default: str = "1") -> bool:
        flag = os.environ.get(name, default).strip().lower()
        return flag not in {"0", "false", "no", "off"}

    @staticmethod
    def _wazuh_configured(settings: WazuhSettings) -> bool:
        try:
            settings.resolved_username()
            settings.resolved_password()
        except ValueError:
            return False
        return True

    @staticmethod
    def _wazuh_tls_verify(settings: WazuhSettings) -> bool | str:
        if settings.ca_path is not None:
            return str(settings.ca_path)
        return settings.verify_tls

    @staticmethod
    @asynccontextmanager
    async def run(app: FastAPI, settings: Settings) -> AsyncIterator[None]:
        log = logging.getLogger("app.core.lifecycle")
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
        outbox, owns_outbox = await AppLifecycle._open_outbox(app, settings)
        qoe, aggregator = AppLifecycle._open_qoe(app, settings)
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
        app.state.qoe = qoe
        consumer: KafkaDnsConsumer | None = None
        consumer_task: asyncio.Task[None] | None = None
        dispatcher_task: asyncio.Task[None] | None = None
        qoe_task: asyncio.Task[None] | None = None
        gauge_task: asyncio.Task[None] | None = None
        wazuh_http: httpx.AsyncClient | None = None
        clickhouse: ClickHouseClient | None = None
        if AppLifecycle.kafka_consumer_enabled():
            consumer = KafkaDnsConsumer(settings, metrics=metrics)
            app.state.kafka_consumer = consumer
            handler = AppLifecycle._kafka_handler(service, metrics)
            consumer_task = asyncio.create_task(
                AppLifecycle._run_consumer(consumer, handler, metrics),
                name="sentinel-kafka-consumer",
            )
        if AppLifecycle._env_enabled(WAZUH_DISPATCHER_ENV) and AppLifecycle._wazuh_configured(
            settings.wazuh
        ):
            wazuh_http = httpx.AsyncClient(
                base_url=settings.wazuh.base_url,
                verify=AppLifecycle._wazuh_tls_verify(settings.wazuh),
                timeout=10.0,
            )
            dispatcher = WazuhOutboxDispatcher(
                outbox,
                WazuhClient(settings.wazuh, wazuh_http),
                batch_size=settings.wazuh.batch_max,
            )
            dispatcher_task = asyncio.create_task(
                AppLifecycle._run_dispatcher(
                    dispatcher,
                    flush_seconds=settings.wazuh.flush_seconds,
                    metrics=metrics,
                ),
                name="sentinel-wazuh-dispatcher",
            )
        else:
            log.info(
                "wazuh dispatcher idle",
                extra={"event": "wazuh_dispatcher_skipped", "error_code": "unconfigured"},
            )
        if aggregator is not None and AppLifecycle._env_enabled(QOE_FLUSH_ENV):
            clickhouse = ClickHouseClient(
                ClickHouseSettingsLike(
                    host=settings.clickhouse.host,
                    http_port=settings.clickhouse.http_port,
                    database=settings.clickhouse.database,
                    username=settings.clickhouse.resolved_username(),
                    password=settings.clickhouse.resolved_password(),
                    secure=settings.clickhouse.secure,
                )
            )
            qoe_task = asyncio.create_task(
                AppLifecycle._run_qoe_flush(
                    aggregator,
                    ClickHouseQoeRepository(clickhouse),
                    metrics,
                ),
                name="sentinel-qoe-flush",
            )
        gauge_task = asyncio.create_task(
            AppLifecycle._run_outbox_gauge(outbox, metrics),
            name="sentinel-outbox-gauge",
        )
        app.state.service_state = ServiceState.READY
        try:
            yield
        finally:
            app.state.service_state = ServiceState.STOPPING
            if consumer is not None:
                await consumer.stop()
            await AppLifecycle._stop_task(consumer_task)
            await AppLifecycle._stop_task(dispatcher_task)
            await AppLifecycle._stop_task(qoe_task)
            await AppLifecycle._stop_task(gauge_task)
            if wazuh_http is not None:
                await wazuh_http.aclose()
            if clickhouse is not None:
                await clickhouse.close()
            if owns_outbox:
                close_fn = getattr(outbox, "close", None)
                if callable(close_fn):
                    await close_fn()
            await qvac.close()
            app.state.service_state = ServiceState.STOPPED

    @staticmethod
    async def _open_outbox(app: FastAPI, settings: Settings) -> tuple[OutboxPort, bool]:
        existing = getattr(app.state, "outbox", None)
        if existing is not None and callable(getattr(existing, "enqueue", None)):
            return cast(OutboxPort, existing), False
        outbox = SqliteOutbox(settings.outbox.path)
        await outbox.start()
        return outbox, True

    @staticmethod
    def _open_qoe(app: FastAPI, settings: Settings) -> tuple[QoeSink | None, QoeAggregator | None]:
        existing = getattr(app.state, "qoe", None)
        if existing is not None and callable(getattr(existing, "observe", None)):
            aggregator = getattr(existing, "aggregator", None)
            return cast(QoeSink, existing), aggregator if isinstance(
                aggregator, QoeAggregator
            ) else None
        thresholds = load_thresholds(settings.qoe_thresholds_path)
        aggregator = QoeAggregator(
            thresholds,
            window_seconds=settings.qoe_window_seconds,
            calculation_version=settings.qoe_calculation_version,
        )
        return DnsQoeSink(aggregator), aggregator

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

    @staticmethod
    async def _run_dispatcher(
        dispatcher: WazuhOutboxDispatcher,
        *,
        flush_seconds: float,
        metrics: SentinelMetrics,
    ) -> None:
        log = logging.getLogger("app.core.lifecycle")
        while True:
            try:
                sent = await dispatcher.run_once()
                if sent:
                    metrics.increment_wazuh_delivery(status="batch", amount=sent)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning(
                    "wazuh dispatcher failed",
                    extra={"event": "wazuh_dispatcher_failed", "error_code": type(exc).__name__},
                )
                metrics.increment_wazuh_delivery(status="error")
            await asyncio.sleep(flush_seconds)

    @staticmethod
    async def _run_qoe_flush(
        aggregator: QoeAggregator,
        repository: ClickHouseQoeRepository,
        metrics: SentinelMetrics,
    ) -> None:
        await QoeFlushWorker(aggregator, repository, metrics).run()

    @staticmethod
    async def _run_outbox_gauge(outbox: OutboxPort, metrics: SentinelMetrics) -> None:
        while True:
            count_fn = getattr(outbox, "pending_count", None)
            if callable(count_fn):
                try:
                    metrics.set_outbox_pending(await count_fn())
                except Exception as exc:
                    logging.getLogger("app.core.lifecycle").warning(
                        "outbox gauge failed",
                        extra={"event": "outbox_gauge_failed", "error_code": type(exc).__name__},
                    )
            await asyncio.sleep(BACKGROUND_POLL_SECONDS)

    @staticmethod
    async def _stop_task(task: asyncio.Task[None] | None) -> None:
        if task is None:
            return
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
