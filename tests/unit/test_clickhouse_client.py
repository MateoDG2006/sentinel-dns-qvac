"""El cliente de ClickHouse clasifica sus fallas como errores recuperables del dominio.

Antes, si ClickHouse estaba caido al abrir la conexion, se escapaba el error
crudo de clickhouse-connect: el codigo que atrapa `RecoverableError` no lo veia
y un reintento se convertia en una excepcion no manejada.
"""

from __future__ import annotations

import asyncio

import pytest

from app.domain.errors import ClickHouseUnavailableError, RecoverableError
from app.infrastructure.clickhouse.client import ClickHouseClient, ClickHouseSettingsLike


def unreachable() -> ClickHouseClient:
    """Cliente contra un puerto donde no escucha nadie: la conexion se rechaza."""
    return ClickHouseClient(
        ClickHouseSettingsLike(host="127.0.0.1", http_port=1, connect_timeout_seconds=1.0)
    )


def test_no_poder_conectar_lanza_el_error_recuperable_del_dominio() -> None:
    with pytest.raises(ClickHouseUnavailableError) as info:
        asyncio.run(unreachable().query_rows("SELECT 1"))
    assert isinstance(info.value, RecoverableError)


def test_insertar_sin_conexion_lanza_el_error_recuperable() -> None:
    with pytest.raises(ClickHouseUnavailableError):
        asyncio.run(unreachable().insert("dns_qoe_1m", [(1,)], ["x"]))


def test_health_no_lanza_aunque_no_pueda_conectar() -> None:
    estado = asyncio.run(unreachable().health())
    assert estado.healthy is False
    assert estado.detail
