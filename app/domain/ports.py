"""Protocols for every external system. Domain code must not import adapters."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from app.domain.schemas import (
    DeliveryResult,
    DependencyHealth,
    NormalizedDnsEvent,
    OutboxRecord,
    QoeWindow,
    QvacCandidate,
    QvacVerdict,
)


class BatchHandler(Protocol):
    async def __call__(self, events: list[NormalizedDnsEvent]) -> None: ...


class QvacInferencePort(Protocol):
    async def start(self) -> None: ...

    async def enrich(self, candidate: QvacCandidate) -> QvacVerdict: ...

    async def health(self) -> DependencyHealth: ...

    async def close(self) -> None: ...


class WazuhEventPort(Protocol):
    async def send_events(self, events: list[str]) -> DeliveryResult: ...


class OutboxPort(Protocol):
    async def enqueue(self, record: OutboxRecord) -> bool: ...

    async def claim_batch(self, limit: int) -> list[OutboxRecord]: ...

    async def mark_delivered(self, ids: list[UUID]) -> None: ...

    async def reschedule(self, ids: list[UUID], retry_at: datetime, reason: str) -> None: ...

    async def mark_dead(self, ids: list[UUID], reason: str) -> None: ...


class ClickHouseQoePort(Protocol):
    async def upsert_windows(self, windows: list[QoeWindow]) -> None: ...

    async def health(self) -> DependencyHealth: ...


class KafkaDnsConsumerPort(Protocol):
    async def run(self, handler: BatchHandler) -> None: ...

    async def stop(self) -> None: ...
