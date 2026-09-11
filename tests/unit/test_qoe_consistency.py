"""Tests de coherencia entre las piezas de C3.

La tabla, el repositorio, el agregador y el dashboard viven en archivos
distintos y en formatos distintos (SQL, Python, JSON, YAML). Nada los obliga a
estar de acuerdo: si alguien agrega una columna al DDL y olvida el repositorio,
o cambia un umbral en el YAML y no el dashboard, cada pieza sigue funcionando
por separado y el error recién aparece en la demo.

Estos tests leen los archivos del repositorio y verifican que coincidan. No
requieren Docker ni ClickHouse, a diferencia de los de integración.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from app.infrastructure.clickhouse.repository import (
    QOE_COLUMNS,
    QOE_LATEST_VIEW,
    QOE_TABLE,
    ClickHouseQoeRepository,
    _to_row,
)
from app.services.qoe import (
    STATUS_CRITICAL,
    STATUS_GOOD,
    STATUS_INSUFFICIENT_DATA,
    STATUS_WARNING,
    QoeWindowResult,
    load_thresholds,
)

INIT_SQL = Path("deploy/clickhouse/init/001_qoe.sql")
DASHBOARD = Path("deploy/grafana/provisioning/dashboards/sentinel-dns.json")
DATASOURCE = Path("deploy/grafana/provisioning/datasources/clickhouse.yaml")
PROVIDER = Path("deploy/grafana/provisioning/dashboards/provider.yaml")
THRESHOLDS = Path("config/qoe_thresholds.yaml")


# --- Lectura de los archivos ------------------------------------------------


def _sql() -> str:
    return INIT_SQL.read_text(encoding="utf-8")


def _table_block() -> str:
    """Cuerpo del CREATE TABLE, desde el nombre hasta el ENGINE."""
    return _sql().split("CREATE TABLE", 1)[1].split("ENGINE", 1)[0]


def _view_block() -> str:
    return _sql().split("CREATE OR REPLACE VIEW", 1)[1]


def ddl_columns() -> list[str]:
    """Columnas del CREATE TABLE, en el orden en que se declaran."""
    return re.findall(r"^\s*`(\w+)`", _table_block(), flags=re.MULTILINE)


def view_computed_columns() -> set[str]:
    """Columnas que la vista agrega a las de la tabla, derivadas del `AS alias`."""
    return set(re.findall(r"\bAS\s+([a-z][a-z0-9_]*)\b", _view_block()))


def ddl_status_values() -> set[str]:
    enum = re.search(r"Enum8\((.*?)\)", _table_block(), flags=re.DOTALL)
    assert enum is not None, "no se encontro el Enum8 de status en el DDL"
    return set(re.findall(r"'(\w+)'\s*=", enum.group(1)))


def dashboard() -> dict[str, Any]:
    return json.loads(DASHBOARD.read_text(encoding="utf-8"))


def panels() -> list[dict[str, Any]]:
    return dashboard()["panels"]


def panel(title: str) -> dict[str, Any]:
    for candidate in panels():
        if candidate["title"] == title:
            return candidate
    raise AssertionError(f"no existe el panel {title!r}")


def datasource() -> dict[str, Any]:
    return yaml.safe_load(DATASOURCE.read_text(encoding="utf-8"))["datasources"][0]


def sample_window(**overrides: Any) -> QoeWindowResult:
    valores: dict[str, Any] = {
        "window_start": datetime(2026, 9, 10, 12, 0, tzinfo=UTC),
        "site_id": "pop-bog",
        "zone_id": "zona-centro",
        "sample_count": 1173,
        "latency_p50_ms": 35.3,
        "latency_p95_ms": 59.9,
        "latency_p99_ms": 65.6,
        "nxdomain_rate": 0.026,
        "servfail_rate": 0.002,
        "timeout_rate": 0.003,
        "saturation_index": 0.0,
        "latency_score": 100.0,
        "resolution_score": 96.9,
        "saturation_score": 100.0,
        "qoe_score": 99.1,
        "status": "good",
        "primary_cause": "nxdomain_elevado",
        "calculation_version": "1.0",
        "updated_at": datetime(2026, 9, 10, 12, 1, tzinfo=UTC),
    }
    valores.update(overrides)
    return QoeWindowResult(**valores)


# --- DDL <-> repositorio <-> agregador --------------------------------------


def test_las_columnas_del_repositorio_coinciden_con_el_ddl() -> None:
    """El INSERT posicional depende de que el orden sea exactamente el mismo."""
    assert tuple(ddl_columns()) == QOE_COLUMNS


def test_la_tabla_tiene_las_19_columnas_de_la_spec() -> None:
    assert len(ddl_columns()) == 19


def test_los_campos_de_la_ventana_coinciden_con_las_columnas() -> None:
    """El agregador produce exactamente lo que la tabla espera, en ese orden."""
    assert tuple(f.name for f in fields(QoeWindowResult)) == QOE_COLUMNS


def test_to_row_respeta_el_orden_de_las_columnas() -> None:
    ventana = sample_window()
    fila = _to_row(ventana)
    assert len(fila) == len(QOE_COLUMNS)
    for posicion, columna in enumerate(QOE_COLUMNS):
        assert fila[posicion] == getattr(ventana, columna), columna


def test_los_estados_del_ddl_coinciden_con_los_del_agregador() -> None:
    """Un estado que el agregador emite y el Enum8 no acepta rompe el INSERT."""
    esperados = {STATUS_GOOD, STATUS_WARNING, STATUS_CRITICAL, STATUS_INSUFFICIENT_DATA}
    assert ddl_status_values() == esperados


def test_los_nombres_de_tabla_y_vista_coinciden_con_el_ddl() -> None:
    sql = _sql()
    assert f"sentinel_dns.{QOE_TABLE}" in sql
    assert f"sentinel_dns.{QOE_LATEST_VIEW}" in sql


def test_la_vista_expone_todas_las_columnas_de_la_tabla() -> None:
    vista = _view_block()
    faltantes = [c for c in QOE_COLUMNS if not re.search(rf"\b{c}\b", vista)]
    assert faltantes == []


def test_la_vista_deduplica_con_final() -> None:
    """Sin FINAL, una ventana reescrita aparece dos veces hasta el merge."""
    assert re.search(r"\bFINAL\b", _view_block())


def test_la_tabla_es_idempotente_por_la_clave_de_ventana() -> None:
    motor = _sql().split("ENGINE", 1)[1]
    assert "ReplacingMergeTree(updated_at)" in motor
    assert "ORDER BY (site_id, zone_id, window_start)" in motor


# --- Repositorio con un cliente falso ---------------------------------------


class FakeClient:
    """Registra las llamadas en vez de hablar con ClickHouse."""

    def __init__(self) -> None:
        self.inserts: list[tuple[str, list[Any], list[str]]] = []

    async def insert(self, table: str, rows: Any, column_names: Any) -> None:
        self.inserts.append((table, list(rows), list(column_names)))


def test_upsert_inserta_en_la_tabla_con_las_columnas_correctas() -> None:
    cliente = FakeClient()
    repo = ClickHouseQoeRepository(cliente)  # type: ignore[arg-type]
    ventanas = [sample_window(), sample_window(zone_id="zona-sur")]

    asyncio.run(repo.upsert_windows(ventanas))

    assert len(cliente.inserts) == 1
    tabla, filas, columnas = cliente.inserts[0]
    assert tabla == QOE_TABLE
    assert tuple(columnas) == QOE_COLUMNS
    assert filas == [_to_row(v) for v in ventanas]


def test_upsert_con_lote_vacio_no_llama_a_clickhouse() -> None:
    cliente = FakeClient()
    repo = ClickHouseQoeRepository(cliente)  # type: ignore[arg-type]
    asyncio.run(repo.upsert_windows([]))
    assert cliente.inserts == []


# --- Dashboard <-> tabla <-> umbrales ---------------------------------------


def test_todos_los_paneles_usan_el_datasource_aprovisionado() -> None:
    uid = datasource()["uid"]
    for p in panels():
        assert p["datasource"]["uid"] == uid, p["title"]
        for target in p["targets"]:
            assert target["datasource"]["uid"] == uid, p["title"]


def test_las_variables_usan_el_datasource_aprovisionado() -> None:
    uid = datasource()["uid"]
    for variable in dashboard()["templating"]["list"]:
        assert variable["datasource"]["uid"] == uid, variable["name"]


def test_los_paneles_leen_de_la_vista_deduplicada() -> None:
    """Leer la tabla cruda mostraria ventanas duplicadas tras un reintento."""
    for p in panels():
        sql = p["targets"][0]["rawSql"]
        assert QOE_LATEST_VIEW in sql, p["title"]


def test_las_queries_solo_referencian_columnas_existentes() -> None:
    """Una columna renombrada en el DDL dejaria un panel vacio sin error visible."""
    disponibles = set(QOE_COLUMNS) | view_computed_columns()
    for p in panels():
        sql = p["targets"][0]["rawSql"]
        # Se descarta todo lo que no es una referencia a columna.
        sql = re.sub(r"\$\{[^}]*\}", "", sql)  # variables del dashboard
        sql = re.sub(r"\$__\w+", "", sql)  # macros de Grafana
        sql = re.sub(r"'[^']*'", "", sql)  # literales
        sql = re.sub(r'"[^"]*"', "", sql)  # alias entre comillas
        identificadores = set(re.findall(r"\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b", sql))
        identificadores -= {"sentinel_dns", QOE_LATEST_VIEW}
        assert identificadores <= disponibles, f"{p['title']}: {identificadores - disponibles}"


def test_los_colores_del_score_coinciden_con_los_umbrales_del_yaml() -> None:
    """Si se cambia good_min en el YAML y no el dashboard, los colores mienten."""
    umbrales = load_thresholds(THRESHOLDS)
    for titulo in ("QoE actual por zona", "Evolución del QoE"):
        pasos = panel(titulo)["fieldConfig"]["defaults"]["thresholds"]["steps"]
        cortes = [paso["value"] for paso in pasos if paso["value"] is not None]
        assert cortes == [umbrales.warning_min, umbrales.good_min], titulo


def test_la_linea_de_muestras_minimas_coincide_con_el_yaml() -> None:
    umbrales = load_thresholds(THRESHOLDS)
    pasos = panel("Volumen de muestras")["fieldConfig"]["defaults"]["thresholds"]["steps"]
    cortes = [paso["value"] for paso in pasos if paso["value"] is not None]
    assert cortes == [umbrales.min_samples]


def test_la_linea_critica_de_latencia_coincide_con_el_yaml() -> None:
    umbrales = load_thresholds(THRESHOLDS)
    p95 = umbrales.defaults.latency_p95_ms
    pasos = panel("Latencia p50 / p95 / p99")["fieldConfig"]["defaults"]["thresholds"]["steps"]
    cortes = [paso["value"] for paso in pasos if paso["value"] is not None]
    assert cortes == [p95.good, p95.critical]


# --- Requisitos de la spec seccion 11 ---------------------------------------


@pytest.mark.parametrize(
    "titulo",
    [
        "QoE actual por zona",
        "Evolución del QoE",
        "Latencia p50 / p95 / p99",
        "Fallos: NXDOMAIN / SERVFAIL / timeout",
        "Causa principal",
        "Matriz sitio × zona",
        "Volumen de muestras",
    ],
)
def test_existe_cada_panel_obligatorio(titulo: str) -> None:
    panel(titulo)


def test_el_score_nunca_se_muestra_sin_sus_subscores() -> None:
    """Spec seccion 11: el score debe leerse junto a sus tres subscores."""
    sql = panel("Subscores")["targets"][0]["rawSql"]
    for subscore in ("latency_score", "resolution_score", "saturation_score"):
        assert subscore in sql


def test_cada_panel_tiene_descripcion() -> None:
    for p in panels():
        assert p.get("description", "").strip(), p["title"]


def test_existen_los_filtros_por_sitio_y_zona() -> None:
    nombres = {v["name"] for v in dashboard()["templating"]["list"]}
    assert {"site", "zone"} <= nombres


def test_todas_las_queries_aplican_los_filtros() -> None:
    for p in panels():
        sql = p["targets"][0]["rawSql"]
        assert "${site:sqlstring}" in sql, p["title"]
        assert "${zone:sqlstring}" in sql, p["title"]
        assert "$__timeFilter(window_start)" in sql, p["title"]


# --- Aprovisionamiento ------------------------------------------------------


def test_el_datasource_apunta_a_los_defaults_de_la_app() -> None:
    """Coincide con ClickHouseSettings de app/core/config.py y con compose.yaml."""
    ds = datasource()
    assert ds["type"] == "grafana-clickhouse-datasource"
    assert ds["jsonData"]["host"] == "clickhouse"
    assert ds["jsonData"]["port"] == 8123
    assert ds["jsonData"]["defaultDatabase"] == "sentinel_dns"


def test_el_datasource_no_versiona_secretos() -> None:
    ds = datasource()
    assert not ds.get("secureJsonData")
    assert "password" not in ds.get("jsonData", {})


def test_el_dashboard_no_se_edita_desde_la_interfaz() -> None:
    """El dashboard es codigo: un checkout limpio debe producir la misma vista."""
    assert dashboard()["editable"] is False
    proveedor = yaml.safe_load(PROVIDER.read_text(encoding="utf-8"))["providers"][0]
    assert proveedor["allowUiUpdates"] is False
    assert proveedor["disableDeletion"] is True
