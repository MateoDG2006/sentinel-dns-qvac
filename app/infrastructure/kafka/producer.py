"""Productor Kafka de eventos DNS normalizados (C1).

Lo usan el simulador sintético y los tests; el agente solo consume. El formato
de cable coincide con lo que espera `KafkaDnsConsumer` (A5): JSON UTF-8 que
valida contra `NormalizedDnsEvent`.

Decisiones:

- La clave del mensaje es `client_hash`. Kafka garantiza orden solo dentro de
  una partición, y las señales temporales (beaconing, tasa por cliente) se
  miden por cliente: con esta clave, los eventos de un mismo cliente llegan en
  el orden en que se emitieron.
- El ground truth se publica en su propio topic y nunca dentro del evento
  analizado (spec sección 12), para que el detector no pueda "ver la respuesta".
- `send()` encola sin esperar la confirmación de cada mensaje; los errores de
  entrega aparecen en `flush()`, que espera todas las confirmaciones pendientes.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from types import TracebackType
from typing import Any, Self

from aiokafka import AIOKafkaProducer  # type: ignore[import-untyped]

from app.constants.kafka import TOPIC_GROUNDTRUTH, TOPIC_NORMALIZED
from app.domain.schemas import NormalizedDnsEvent

__all__ = ["KafkaEventProducer"]


class KafkaEventProducer:
    """Publica eventos y su ground truth en los topics congelados."""

    def __init__(
        self,
        bootstrap_servers: str,
        *,
        topic_events: str = TOPIC_NORMALIZED,
        topic_groundtruth: str = TOPIC_GROUNDTRUTH,
        request_timeout_ms: int = 10_000,
    ) -> None:
        self._bootstrap_servers = bootstrap_servers
        self._topic_events = topic_events
        self._topic_groundtruth = topic_groundtruth
        self._request_timeout_ms = request_timeout_ms
        self._producer: AIOKafkaProducer | None = None
        self._pending: list[asyncio.Future[Any]] = []

    async def start(self) -> None:
        if self._producer is not None:
            return
        producer = AIOKafkaProducer(
            bootstrap_servers=self._bootstrap_servers,
            request_timeout_ms=self._request_timeout_ms,
            acks="all",
            enable_idempotence=True,
            linger_ms=5,
        )
        await producer.start()
        self._producer = producer

    async def close(self) -> None:
        producer, self._producer = self._producer, None
        if producer is None:
            return
        try:
            await self._await_pending()
        finally:
            await producer.stop()

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.close()

    def _require(self) -> AIOKafkaProducer:
        if self._producer is None:
            raise RuntimeError("el productor no fue iniciado; llamar a start()")
        return self._producer

    async def publish_event(self, event: NormalizedDnsEvent) -> None:
        """Encola un evento en `dns.telemetry.normalized`."""
        future = await self._require().send(
            self._topic_events,
            event.model_dump_json().encode("utf-8"),
            key=event.client_hash.encode("utf-8"),
        )
        self._pending.append(future)

    async def publish_ground_truth(self, event_id: str, labels: Mapping[str, Any]) -> None:
        """Encola la etiqueta real de un evento en el topic de evaluación."""
        payload = {"event_id": event_id, **labels}
        future = await self._require().send(
            self._topic_groundtruth,
            json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            key=event_id.encode("utf-8"),
        )
        self._pending.append(future)

    async def flush(self) -> int:
        """Espera las confirmaciones pendientes. Devuelve cuántos mensajes confirmó."""
        return await self._await_pending()

    async def _await_pending(self) -> int:
        pending, self._pending = self._pending, []
        if pending:
            # Si alguna entrega falló, se propaga la primera excepción.
            await asyncio.gather(*pending)
        return len(pending)
