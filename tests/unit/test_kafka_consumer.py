"""Kafka consumer: frozen topics, DLQ, backpressure. Does not start C1's broker."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from aiokafka import TopicPartition

from app.constants.health import KAFKA_CONNECTING_DETAIL
from app.constants.kafka import TOPIC_DLQ, TOPIC_NORMALIZED
from app.core.config import Settings
from app.core.lifecycle import AppLifecycle
from app.domain.enums import DependencyStatus
from app.domain.errors import KafkaBackpressureError
from app.domain.schemas import NormalizedDnsEvent
from app.infrastructure.kafka.consumer import KafkaDnsConsumer
from app.observability.metrics import SentinelMetrics


class FakeRecord:
    def __init__(self, value: bytes) -> None:
        self.value = value


class FakeDlq:
    def __init__(self) -> None:
        self.items: list[tuple[bytes, str]] = []

    async def publish(self, payload: bytes, reason: str) -> None:
        self.items.append((payload, reason))


def _event_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_id": str(uuid4()),
        "event_ts": datetime.now(UTC).isoformat(),
        "observed_at": datetime.now(UTC).isoformat(),
        "site_id": "pop-1",
        "zone_id": "zone-a",
        "resolver_id": "resolver-1",
        "client_hash": "client-hash-1",
        "qname": "www.example.com",
        "qtype": "A",
        "rcode": "NOERROR",
        "latency_ms": 25.0,
        "response_bytes": 128,
        "timed_out": False,
        "synthetic": True,
    }
    payload.update(overrides)
    return payload


def _batch(payloads: list[bytes]) -> dict[TopicPartition, list[FakeRecord]]:
    partition = TopicPartition(TOPIC_NORMALIZED, 0)
    return {partition: [FakeRecord(item) for item in payloads]}


async def test_valid_record_is_handed_to_prediction_handler() -> None:
    received: list[NormalizedDnsEvent] = []

    async def handler(events: list[NormalizedDnsEvent]) -> None:
        received.extend(events)

    payload = json.dumps(_event_payload()).encode("utf-8")
    consumer = KafkaDnsConsumer(Settings(), dlq=FakeDlq())
    await consumer.handle_records(_batch([payload]), handler=handler)
    assert len(received) == 1
    assert received[0].synthetic is True
    assert received[0].qname == "www.example.com"


async def test_invalid_and_non_synthetic_records_go_to_dlq() -> None:
    dlq = FakeDlq()
    received: list[NormalizedDnsEvent] = []

    async def handler(events: list[NormalizedDnsEvent]) -> None:
        received.extend(events)

    invalid = b"{not-json"
    non_synthetic = json.dumps(_event_payload(synthetic=False)).encode("utf-8")
    consumer = KafkaDnsConsumer(Settings(), dlq=dlq)
    await consumer.handle_records(_batch([invalid, non_synthetic]), handler=handler)
    assert received == []
    assert len(dlq.items) == 2
    assert dlq.items[0][0] == invalid
    assert dlq.items[1][0] == non_synthetic


async def test_clock_skew_goes_to_dlq_without_calling_handler() -> None:
    dlq = FakeDlq()
    received: list[NormalizedDnsEvent] = []

    async def handler(events: list[NormalizedDnsEvent]) -> None:
        received.extend(events)

    skewed = datetime.now(UTC) - timedelta(hours=2)
    payload = json.dumps(
        _event_payload(event_ts=skewed.isoformat(), observed_at=skewed.isoformat())
    ).encode("utf-8")
    consumer = KafkaDnsConsumer(Settings(), dlq=dlq)
    await consumer.handle_records(_batch([payload]), handler=handler)
    assert received == []
    assert len(dlq.items) == 1
    assert dlq.items[0][1] == "clock_skew"


async def test_handler_backpressure_propagates() -> None:
    async def handler(events: list[NormalizedDnsEvent]) -> None:
        _ = events
        raise KafkaBackpressureError()

    payload = json.dumps(_event_payload()).encode("utf-8")
    consumer = KafkaDnsConsumer(Settings(), dlq=FakeDlq())
    with pytest.raises(KafkaBackpressureError):
        await consumer.handle_records(_batch([payload]), handler=handler)


async def test_consumer_uses_frozen_topics_and_own_group() -> None:
    settings = Settings()
    assert settings.kafka.topic_normalized == TOPIC_NORMALIZED
    assert settings.kafka.topic_dlq == TOPIC_DLQ
    assert settings.kafka.consumer_group == "sentinel-dns"
    assert TOPIC_NORMALIZED == "dns.telemetry.normalized"
    assert TOPIC_DLQ == "sentinel.dns.dlq"


async def test_dlq_increments_kafka_metric() -> None:
    metrics = SentinelMetrics()
    consumer = KafkaDnsConsumer(Settings(), metrics=metrics, dlq=FakeDlq())

    async def handler(events: list[NormalizedDnsEvent]) -> None:
        _ = events

    await consumer.handle_records(_batch([b"nope"]), handler=handler)
    rendered = metrics.render().decode("utf-8")
    assert 'sentinel_dns_events_total{source="kafka",status="dlq"}' in rendered


def test_unit_tests_disable_kafka_consumer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_ENABLE_KAFKA_CONSUMER", "0")
    assert AppLifecycle.kafka_consumer_enabled() is False
    monkeypatch.setenv("SENTINEL_ENABLE_KAFKA_CONSUMER", "1")
    assert AppLifecycle.kafka_consumer_enabled() is True


async def test_kafka_health_is_connecting_before_broker() -> None:
    consumer = KafkaDnsConsumer(Settings())
    health = await consumer.health()
    assert health.status is DependencyStatus.DEGRADED
    assert health.detail == KAFKA_CONNECTING_DETAIL
