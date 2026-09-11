"""Tests de integración del repositorio de QoE contra un ClickHouse real (C3).

Levantan un contenedor efímero, le aplican `deploy/clickhouse/init/001_qoe.sql`
y ejercitan el camino completo: agregador -> repositorio -> tabla -> lectura.

Lo que estos tests protegen y los unitarios no pueden:

- Que el DDL sea SQL válido para la versión de ClickHouse que usa la demo.
- Que el orden y los tipos de `QOE_COLUMNS` coincidan con el CREATE TABLE.
- Que reescribir una ventana la reemplace en vez de duplicarla, que es el
  criterio de "escritura idempotente" del issue C3.

Requieren Docker. Si no está disponible, se omiten en vez de fallar.
"""

from __future__ import annotations

import asyncio
import random
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("testcontainers", reason="los tests de integración requieren testcontainers")

from testcontainers.core.container import DockerContainer  # noqa: E402


def _docker_disponible() -> bool:
    """Tener testcontainers instalado no alcanza: el motor tiene que responder."""
    try:
        import docker

        docker.from_env().ping()
    except Exception:  # noqa: BLE001 - cualquier fallo significa "no hay Docker"
        return False
    return True


pytestmark = pytest.mark.skipif(
    not _docker_disponible(), reason="Docker no está disponible en este entorno"
)

from app.infrastructure.clickhouse.client import (  # noqa: E402
    ClickHouseClient,
    ClickHouseSettingsLike,
)
from app.infrastructure.clickhouse.repository import (  # noqa: E402
    QOE_COLUMNS,
    ClickHouseQoeRepository,
)
from app.services.qoe import QoeAggregator, QoeSample, load_thresholds  # noqa: E402

CLICKHOUSE_IMAGE = "clickhouse/clickhouse-server:24.8-alpine"
HTTP_PORT = 8123
INIT_SQL = Path("deploy/clickhouse/init/001_qoe.sql")
THRESHOLDS = Path("config/qoe_thresholds.yaml")
READY_TIMEOUT_S = 90


def _statements(sql: str) -> list[str]:
    """Separa el archivo en sentencias.

    Un `split(";")` ingenuo no sirve: el DDL tiene comentarios `--` y literales
    `COMMENT '...'` que pueden contener punto y coma. El recorrido lleva estado
    de cadena y de comentario para cortar solo en los separadores reales.
    """
    sentencias: list[str] = []
    actual: list[str] = []
    en_cadena = False
    en_comentario = False
    i = 0
    while i < len(sql):
        char = sql[i]
        if en_comentario:
            if char == "\n":
                en_comentario = False
                actual.append(char)
            i += 1
            continue
        if en_cadena:
            actual.append(char)
            if char == "'":
                # '' escapa una comilla dentro del literal.
                if i + 1 < len(sql) and sql[i + 1] == "'":
                    actual.append(sql[i + 1])
                    i += 2
                    continue
                en_cadena = False
            i += 1
            continue
        if char == "'":
            en_cadena = True
            actual.append(char)
        elif char == "-" and sql.startswith("--", i):
            en_comentario = True
            i += 2
            continue
        elif char == ";":
            sentencias.append("".join(actual))
            actual = []
        else:
            actual.append(char)
        i += 1
    sentencias.append("".join(actual))
    return [s.strip() for s in sentencias if s.strip()]


def _execute(base_url: str, sql: str) -> str:
    request = urllib.request.Request(base_url, data=sql.encode("utf-8"))
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def _wait_until_ready(base_url: str) -> None:
    deadline = time.monotonic() + READY_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            if _execute(base_url, "SELECT 1").strip() == "1":
                return
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(1.0)
    raise RuntimeError("ClickHouse no respondió dentro del tiempo previsto")


@pytest.fixture(scope="module")
def clickhouse_url() -> Iterator[str]:
    """Contenedor efímero con el esquema del repositorio ya aplicado."""
    container = DockerContainer(CLICKHOUSE_IMAGE).with_exposed_ports(HTTP_PORT)
    container.with_env("CLICKHOUSE_SKIP_USER_SETUP", "1")
    with container:
        url = (
            f"http://{container.get_container_host_ip()}:"
            f"{container.get_exposed_port(HTTP_PORT)}/"
        )
        _wait_until_ready(url)
        for statement in _statements(INIT_SQL.read_text(encoding="utf-8")):
            _execute(url, statement)
        yield url


@pytest.fixture
def repository(clickhouse_url: str) -> Iterator[ClickHouseQoeRepository]:
    host, port = clickhouse_url.removeprefix("http://").rstrip("/").split(":")
    client = ClickHouseClient(ClickHouseSettingsLike(host=host, http_port=int(port)))
    yield ClickHouseQoeRepository(client)
    asyncio.run(client.close())


@pytest.fixture(autouse=True)
def tabla_vacia(clickhouse_url: str) -> None:
    """Cada test parte de una tabla limpia."""
    _execute(clickhouse_url, "TRUNCATE TABLE sentinel_dns.dns_qoe_1m")


def build_windows(*, site_id: str = "pop-bog", zone_id: str = "zona-centro") -> list[Any]:
    """Ventanas reales producidas por el agregador, no fixtures inventadas."""
    thresholds = load_thresholds(THRESHOLDS)
    inicio = datetime(2026, 9, 10, 12, 0, 0, tzinfo=UTC)
    aggregator = QoeAggregator(thresholds, window_seconds=60)
    for i in range(120):
        aggregator.observe(
            QoeSample(
                event_ts=inicio + timedelta(seconds=i % 60),
                site_id=site_id,
                zone_id=zone_id,
                rcode="NOERROR",
                latency_ms=30.0 + random.Random(i).random(),
                timed_out=False,
            )
        )
    return aggregator.flush_all(inicio + timedelta(minutes=5))


def contar(url: str) -> int:
    return int(_execute(url, "SELECT count() FROM sentinel_dns.dns_qoe_1m FINAL").strip())


# --- Esquema ----------------------------------------------------------------


def test_el_ddl_del_repositorio_crea_la_tabla_esperada(clickhouse_url: str) -> None:
    columnas = _execute(
        clickhouse_url,
        "SELECT name FROM system.columns WHERE database='sentinel_dns' "
        "AND table='dns_qoe_1m' ORDER BY position",
    ).split()
    assert tuple(columnas) == QOE_COLUMNS


def test_la_tabla_usa_replacingmergetree_ordenado_por_la_clave_de_ventana(
    clickhouse_url: str,
) -> None:
    engine = _execute(
        clickhouse_url,
        "SELECT engine_full FROM system.tables "
        "WHERE database='sentinel_dns' AND name='dns_qoe_1m'",
    )
    assert "ReplacingMergeTree(updated_at)" in engine
    assert "ORDER BY (site_id, zone_id, window_start)" in engine


def test_existe_la_vista_de_lectura(clickhouse_url: str) -> None:
    vistas = _execute(
        clickhouse_url,
        "SELECT name FROM system.tables WHERE database='sentinel_dns' AND engine='View'",
    ).split()
    assert "dns_qoe_1m_latest" in vistas


def test_el_ddl_es_reejecutable(clickhouse_url: str) -> None:
    """El init script corre en cada arranque: no debe fallar si ya existe."""
    for statement in _statements(INIT_SQL.read_text(encoding="utf-8")):
        _execute(clickhouse_url, statement)


# --- Escritura y lectura ----------------------------------------------------


def test_una_ventana_escrita_se_lee_con_los_mismos_valores(
    repository: ClickHouseQoeRepository, clickhouse_url: str
) -> None:
    ventanas = build_windows()
    asyncio.run(repository.upsert_windows(ventanas))
    assert contar(clickhouse_url) == len(ventanas)

    esperada = ventanas[0]
    fila = asyncio.run(
        repository.fetch_window(esperada.site_id, esperada.zone_id, esperada.window_start)
    )
    assert fila is not None
    assert len(fila) == len(QOE_COLUMNS)

    leida = dict(zip(QOE_COLUMNS, fila, strict=True))
    assert leida["sample_count"] == esperada.sample_count
    assert leida["status"] == esperada.status
    assert leida["primary_cause"] == esperada.primary_cause
    assert leida["calculation_version"] == esperada.calculation_version
    assert leida["qoe_score"] == pytest.approx(esperada.qoe_score, abs=0.01)
    assert leida["latency_p95_ms"] == pytest.approx(esperada.latency_p95_ms, abs=0.01)


def test_reescribir_una_ventana_la_reemplaza_en_vez_de_duplicarla(
    repository: ClickHouseQoeRepository, clickhouse_url: str
) -> None:
    """Criterio de escritura idempotente del issue C3."""
    ventanas = build_windows()
    asyncio.run(repository.upsert_windows(ventanas))
    antes = contar(clickhouse_url)

    original = ventanas[0]
    corregida = replace(
        original,
        qoe_score=42.0,
        status="critical",
        updated_at=original.updated_at + timedelta(minutes=5),
    )
    asyncio.run(repository.upsert_windows([corregida]))

    assert contar(clickhouse_url) == antes
    fila = asyncio.run(
        repository.fetch_window(original.site_id, original.zone_id, original.window_start)
    )
    assert fila is not None
    leida = dict(zip(QOE_COLUMNS, fila, strict=True))
    assert leida["qoe_score"] == pytest.approx(42.0, abs=0.01)
    assert leida["status"] == "critical"


def test_reescribir_con_updated_at_anterior_no_pisa_la_version_vigente(
    repository: ClickHouseQoeRepository, clickhouse_url: str
) -> None:
    """Una entrega tardía no debe revertir una ventana ya corregida."""
    ventanas = build_windows()
    asyncio.run(repository.upsert_windows(ventanas))
    original = ventanas[0]

    vieja = replace(
        original,
        qoe_score=1.0,
        updated_at=original.updated_at - timedelta(minutes=10),
    )
    asyncio.run(repository.upsert_windows([vieja]))

    fila = asyncio.run(
        repository.fetch_window(original.site_id, original.zone_id, original.window_start)
    )
    assert fila is not None
    leida = dict(zip(QOE_COLUMNS, fila, strict=True))
    assert leida["qoe_score"] == pytest.approx(original.qoe_score, abs=0.01)


def test_cada_sitio_y_zona_ocupa_su_propia_fila(
    repository: ClickHouseQoeRepository, clickhouse_url: str
) -> None:
    asyncio.run(repository.upsert_windows(build_windows(zone_id="zona-centro")))
    asyncio.run(repository.upsert_windows(build_windows(zone_id="zona-sur")))
    asyncio.run(repository.upsert_windows(build_windows(site_id="pop-mde")))

    combinaciones = _execute(
        clickhouse_url,
        "SELECT count() FROM (SELECT DISTINCT site_id, zone_id FROM sentinel_dns.dns_qoe_1m)",
    ).strip()
    assert int(combinaciones) == 3


def test_un_lote_vacio_no_escribe_ni_falla(
    repository: ClickHouseQoeRepository, clickhouse_url: str
) -> None:
    asyncio.run(repository.upsert_windows([]))
    assert contar(clickhouse_url) == 0


def test_una_ventana_inexistente_devuelve_none(repository: ClickHouseQoeRepository) -> None:
    fila = asyncio.run(
        repository.fetch_window("pop-inexistente", "zona-x", datetime(2026, 1, 1, tzinfo=UTC))
    )
    assert fila is None


# --- Salud ------------------------------------------------------------------


def test_health_reporta_la_conexion_viva(repository: ClickHouseQoeRepository) -> None:
    estado = asyncio.run(repository.health())
    assert estado.healthy is True
    assert estado.detail is None
    assert estado.checked_at.tzinfo is not None


def test_health_no_lanza_cuando_el_host_no_existe() -> None:
    """Un fallo de dependencia debe reportarse, nunca propagarse."""
    client = ClickHouseClient(
        ClickHouseSettingsLike(
            host="127.0.0.1", http_port=1, connect_timeout_seconds=1.0
        )
    )
    estado = asyncio.run(client.health())
    assert estado.healthy is False
    assert estado.detail
