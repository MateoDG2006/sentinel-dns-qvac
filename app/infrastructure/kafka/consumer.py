"""Kafka consumer for normalized DNS events. Manual commits after the batch handler.

C1 owns the broker, topic init, simulator, and `producer.py`. This adapter only
consumes `dns.telemetry.normalized` with an exclusive group and writes poison
pills to `sentinel.dns.dlq`.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import Protocol

from aiokafka import (  # type: ignore[import-untyped]
    AIOKafkaConsumer,
    AIOKafkaProducer,
    TopicPartition,
)
from pydantic import ValidationError

from app.constants.kafka import (
    BACKPRESSURE_PAUSE_SECONDS,
    DLQ_REASON_HEADER,
    TOPIC_DLQ,
    TOPIC_NORMALIZED,
)
from app.core.config import Settings
from app.domain.enums import EventSource
from app.domain.errors import KafkaBackpressureError
from app.domain.ports import BatchHandler
from app.domain.schemas import NormalizedDnsEvent
from app.observability.metrics import SentinelMetrics
from app.utils.time import UtcDateTime


class DlqPublisher(Protocol):
    async def publish(self, payload: bytes, reason: str) -> None: ...


class KafkaRecord(Protocol):
    value: bytes | None


class KafkaDlqPublisher:
    """Publish the original bytes to C1's DLQ topic. Reason stays in a header, not logs."""

    def __init__(self, producer: AIOKafkaProducer, topic: str = TOPIC_DLQ) -> None:
        self._producer = producer
        self._topic = topic

    async def publish(self, payload: bytes, reason: str) -> None:
        await self._producer.send_and_wait(
            self._topic,
            payload,
            headers=[(DLQ_REASON_HEADER, reason.encode("utf-8"))],
        )


class KafkaDnsConsumer:
    """Own consumer group. Does not change BIND9, Vector, or C1's producer."""

    def __init__(
        self,
        settings: Settings,
        *,
        metrics: SentinelMetrics | None = None,
        dlq: DlqPublisher | None = None,
    ) -> None:
        self._settings = settings
        self._metrics = metrics
        self._dlq = dlq
        self._handler: BatchHandler | None = None
        self._log = logging.getLogger("app.infrastructure.kafka")
        self._consumer: AIOKafkaConsumer | None = None
        self._producer: AIOKafkaProducer | None = None
        self._stopped = False

    async def run(self, handler: BatchHandler) -> None:
        self._handler = handler
        kafka = self._settings.kafka
        topic = kafka.topic_normalized or TOPIC_NORMALIZED
        self._consumer = AIOKafkaConsumer(
            topic,
            bootstrap_servers=kafka.bootstrap_servers,
            group_id=kafka.consumer_group,
            enable_auto_commit=False,
            auto_offset_reset="earliest",
            max_poll_records=kafka.poll_max_records,
            request_timeout_ms=4000,
        )
        self._producer = AIOKafkaProducer(
            bootstrap_servers=kafka.bootstrap_servers,
            request_timeout_ms=4000,
        )
        await self._producer.start()
        await self._consumer.start()
        if self._dlq is None:
            self._dlq = KafkaDlqPublisher(self._producer, topic=kafka.topic_dlq)
        self._log.info(
            "kafka_consumer_started",
            extra={"event": "kafka_consumer_started", "source": EventSource.KAFKA.value},
        )
        try:
            while not self._stopped:
                batch = await self._consumer.getmany(
                    timeout_ms=1000,
                    max_records=kafka.poll_max_records,
                )
                if not batch:
                    continue
                try:
                    await self.handle_records(batch)
                except KafkaBackpressureError:
                    self._log.info(
                        "kafka_backpressure_pause",
                        extra={
                            "event": "kafka_backpressure_pause",
                            "source": EventSource.KAFKA.value,
                        },
                    )
                    self._consumer.pause(*batch.keys())
                    await asyncio.sleep(BACKPRESSURE_PAUSE_SECONDS)
                    self._consumer.resume(*self._consumer.paused())
                    continue
                await self._consumer.commit()
        finally:
            await self.stop()

    async def stop(self) -> None:
        self._stopped = True
        consumer = self._consumer
        producer = self._producer
        self._consumer = None
        self._producer = None
        if consumer is not None:
            await consumer.stop()
        if producer is not None:
            await producer.stop()

    async def handle_records(
        self,
        batch: dict[TopicPartition, list[KafkaRecord]],
        handler: BatchHandler | None = None,
    ) -> None:
        bound = handler or self._handler
        if bound is None:
            raise RuntimeError("kafka consumer has no batch handler")
        events: list[NormalizedDnsEvent] = []
        for _partition, records in batch.items():
            for record in records:
                payload = record.value or b""
                event = await self._decode(payload)
                if event is None:
                    continue
                if self._clock_skewed(event):
                    await self._drop(payload, "clock_skew")
                    continue
                events.append(event)
        if not events:
            return
        await bound(events)

    def _clock_skewed(self, event: NormalizedDnsEvent) -> bool:
        now = UtcDateTime.ensure(datetime.now(UTC))
        skew = abs((event.event_ts - now).total_seconds())
        return skew > self._settings.clock_skew_tolerance_seconds

    async def _drop(self, payload: bytes, reason: str) -> None:
        self._log.info(
            "kafka_event_dlq",
            extra={
                "event": "kafka_event_dlq",
                "error_code": reason,
                "source": EventSource.KAFKA.value,
            },
        )
        if self._dlq is not None:
            await self._dlq.publish(payload, reason)
        if self._metrics is not None:
            self._metrics.increment_events(
                source=EventSource.KAFKA.value,
                status="dlq",
                amount=1,
            )

    async def _decode(self, payload: bytes) -> NormalizedDnsEvent | None:
        try:
            raw = json.loads(payload.decode("utf-8"))
            return NormalizedDnsEvent.model_validate(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as exc:
            await self._drop(payload, type(exc).__name__)
            return None
