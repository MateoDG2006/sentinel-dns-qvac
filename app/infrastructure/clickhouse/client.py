"""Cliente de ClickHouse para Sentinel-DNS.

`clickhouse-connect` expone una API sincrona, asi que cada llamada de red se
ejecuta en un hilo aparte para no bloquear el event loop del agente.

El cliente no conoce el dominio: solo abre la conexion, inserta filas y reporta
salud. El mapeo de ventanas QoE a columnas vive en ``repository.py``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import clickhouse_connect
from clickhouse_connect.driver.client import Client

# Error del dominio (RecoverableError): quien atrape los errores recuperables de
# la app atrapa tambien las caidas de ClickHouse.
from app.domain.errors import ClickHouseUnavailableError

__all__ = ["ClickHouseClient", "ClickHouseSettingsLike", "DependencyState"]


@dataclass(frozen=True, slots=True)
class ClickHouseSettingsLike:
    """Parametros de conexion.

    Refleja `ClickHouseSettings` de app/core/config.py. Se declara aparte para
    que la infraestructura sea utilizable y testeable sin arrastrar toda la
    configuracion de la aplicacion.
    """

    host: str = "clickhouse"
    http_port: int = 8123
    database: str = "sentinel_dns"
    username: str | None = None
    password: str | None = None
    secure: bool = False
    connect_timeout_seconds: float = 5.0
    query_timeout_seconds: float = 30.0


@dataclass(frozen=True, slots=True)
class DependencyState:
    """Salud de la dependencia. Se traduce a `DependencyHealth` en el borde."""

    name: str
    healthy: bool
    detail: str | None
    checked_at: datetime


class ClickHouseClient:
    """Conexion perezosa a ClickHouse con operaciones asincronas."""

    def __init__(self, settings: ClickHouseSettingsLike) -> None:
        self._settings = settings
        self._client: Client | None = None
        # Protege la creacion de la conexion: varias corrutinas pueden llamar a
        # start() al mismo tiempo durante el arranque.
        self._lock = asyncio.Lock()

    @property
    def database(self) -> str:
        return self._settings.database

    async def start(self) -> None:
        """Abre la conexion si todavia no existe."""
        async with self._lock:
            if self._client is not None:
                return
            # clickhouse-connect se conecta al crear el cliente: si ClickHouse
            # esta caido, falla aca y hay que clasificarlo como recuperable.
            try:
                self._client = await asyncio.to_thread(self._connect)
            except Exception as exc:  # noqa: BLE001 - se reclasifica como recuperable
                raise ClickHouseUnavailableError(f"no se pudo conectar: {exc}") from exc

    def _connect(self) -> Client:
        s = self._settings
        return clickhouse_connect.get_client(
            host=s.host,
            port=s.http_port,
            database=s.database,
            username=s.username or "default",
            password=s.password or "",
            secure=s.secure,
            connect_timeout=s.connect_timeout_seconds,
            send_receive_timeout=s.query_timeout_seconds,
        )

    async def close(self) -> None:
        async with self._lock:
            client, self._client = self._client, None
        if client is not None:
            await asyncio.to_thread(client.close)

    async def _require(self) -> Client:
        if self._client is None:
            await self.start()
        client = self._client
        if client is None:  # pragma: no cover - start() siempre asigna o lanza
            raise ClickHouseUnavailableError("no hay conexion con ClickHouse")
        return client

    async def insert(
        self,
        table: str,
        rows: Sequence[Sequence[Any]],
        column_names: Sequence[str],
    ) -> None:
        """Inserta filas. No hace nada si `rows` esta vacio."""
        if not rows:
            return
        client = await self._require()
        try:
            await asyncio.to_thread(
                client.insert,
                table,
                list(rows),
                column_names=list(column_names),
                database=self._settings.database,
            )
        except Exception as exc:  # noqa: BLE001 - se reclasifica como recuperable
            raise ClickHouseUnavailableError(f"fallo al insertar en {table}: {exc}") from exc

    async def query_rows(
        self, sql: str, parameters: dict[str, Any] | None = None
    ) -> list[tuple[Any, ...]]:
        """Ejecuta una consulta y devuelve sus filas como tuplas."""
        client = await self._require()
        try:
            result = await asyncio.to_thread(client.query, sql, parameters or {})
        except Exception as exc:  # noqa: BLE001
            raise ClickHouseUnavailableError(f"fallo la consulta: {exc}") from exc
        # clickhouse-connect tipa las filas como Sequence; se convierten
        # explicitamente para que el tipo declarado sea verdadero.
        return [tuple(row) for row in result.result_rows]

    async def health(self) -> DependencyState:
        """Comprueba que la conexion responde. Nunca lanza."""
        now = datetime.now(UTC)
        try:
            rows = await self.query_rows("SELECT 1")
        except Exception as exc:  # noqa: BLE001 - health jamas debe propagar
            return DependencyState("clickhouse", False, str(exc)[:200], now)
        ok = bool(rows) and rows[0][0] == 1
        return DependencyState("clickhouse", ok, None if ok else "respuesta inesperada", now)
