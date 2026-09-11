"""Escritura de ventanas QoE en ClickHouse.

Implementa el puerto ``ClickHouseQoePort`` de la spec seccion 8.

La idempotencia no se resuelve aca sino en el motor de la tabla: `dns_qoe_1m`
es un ``ReplacingMergeTree(updated_at)`` ordenado por
``(site_id, zone_id, window_start)``. Reinsertar una ventana ya escrita
reemplaza la version anterior en el merge, y las lecturas usan la vista
`dns_qoe_1m_latest`, que aplica `FINAL`. Por eso el repositorio solo necesita
insertar: no borra, no consulta antes de escribir y no lleva estado.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.infrastructure.clickhouse.client import ClickHouseClient, DependencyState
from app.services.qoe import QoeWindowResult

__all__ = ["ClickHouseQoeRepository", "QOE_COLUMNS", "QOE_TABLE", "QOE_LATEST_VIEW"]

# Nombres congelados: coinciden con app/constants/clickhouse.py y con el DDL de
# deploy/clickhouse/init/001_qoe.sql. Cambiarlos requiere un ADR.
QOE_TABLE = "dns_qoe_1m"
QOE_LATEST_VIEW = "dns_qoe_1m_latest"

# El orden debe coincidir exactamente con el CREATE TABLE.
QOE_COLUMNS: tuple[str, ...] = (
    "window_start",
    "site_id",
    "zone_id",
    "sample_count",
    "latency_p50_ms",
    "latency_p95_ms",
    "latency_p99_ms",
    "nxdomain_rate",
    "servfail_rate",
    "timeout_rate",
    "saturation_index",
    "latency_score",
    "resolution_score",
    "saturation_score",
    "qoe_score",
    "status",
    "primary_cause",
    "calculation_version",
    "updated_at",
)


def _to_row(window: QoeWindowResult) -> tuple[Any, ...]:
    """Convierte una ventana calculada en una fila, en el orden de la tabla."""
    return (
        window.window_start,
        window.site_id,
        window.zone_id,
        window.sample_count,
        window.latency_p50_ms,
        window.latency_p95_ms,
        window.latency_p99_ms,
        window.nxdomain_rate,
        window.servfail_rate,
        window.timeout_rate,
        window.saturation_index,
        window.latency_score,
        window.resolution_score,
        window.saturation_score,
        window.qoe_score,
        window.status,
        window.primary_cause,
        window.calculation_version,
        window.updated_at,
    )


class ClickHouseQoeRepository:
    """Persiste ventanas QoE de forma idempotente."""

    def __init__(self, client: ClickHouseClient, *, table: str = QOE_TABLE) -> None:
        self._client = client
        self._table = table

    async def upsert_windows(self, windows: Sequence[QoeWindowResult]) -> None:
        """Escribe un lote de ventanas. Reescribir una ventana la reemplaza."""
        if not windows:
            return
        await self._client.insert(
            self._table,
            [_to_row(window) for window in windows],
            QOE_COLUMNS,
        )

    async def fetch_window(
        self, site_id: str, zone_id: str, window_start: Any
    ) -> tuple[Any, ...] | None:
        """Lee una ventana deduplicada. Pensado para tests y diagnostico."""
        rows = await self._client.query_rows(
            f"SELECT {', '.join(QOE_COLUMNS)} FROM {QOE_LATEST_VIEW} "
            "WHERE site_id = {site:String} AND zone_id = {zone:String} "
            "AND window_start = {start:DateTime64(3, 'UTC')}",
            {"site": site_id, "zone": zone_id, "start": window_start},
        )
        return rows[0] if rows else None

    async def health(self) -> DependencyState:
        return await self._client.health()
