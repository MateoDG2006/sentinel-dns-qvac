"""Tests del agregador de QoE (tarea C2).

Cubren tres capas:

1. Carga y validacion de ``config/qoe_thresholds.yaml``.
2. La matematica pura: normalizacion, subscores y percentiles.
3. El agregador: ventanas fijas, buckets excluyentes, estados y causa principal.

La formula de referencia es la de la spec seccion 9. Varios tests recalculan el
resultado esperado a mano en vez de reusar el codigo bajo prueba, para que un
cambio silencioso en los pesos rompa el test.
"""

import asyncio
import math
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from app.services.qoe import (
    CAUSE_INSUFFICIENT,
    CAUSE_LATENCY,
    CAUSE_NXDOMAIN,
    CAUSE_SATURATION,
    RCODE_NXDOMAIN,
    RCODE_SERVFAIL,
    RCODE_TIMEOUT,
    STATUS_CRITICAL,
    STATUS_GOOD,
    STATUS_INSUFFICIENT_DATA,
    STATUS_WARNING,
    MetricThresholds,
    QoeAggregator,
    QoeSample,
    load_thresholds,
    normalize,
    subscore,
)

THRESHOLDS_PATH = Path("config/qoe_thresholds.yaml")
T0 = datetime(2026, 9, 10, 12, 0, 0, tzinfo=UTC)
AFTER_WINDOW = T0 + timedelta(seconds=120)


@pytest.fixture
def thresholds():
    return load_thresholds(THRESHOLDS_PATH)


def sample(
    *,
    offset_s: int = 0,
    latency_ms: float | None = 30.0,
    rcode: str = "NOERROR",
    timed_out: bool = False,
    site_id: str = "pop-bog",
    zone_id: str = "zona-centro",
) -> QoeSample:
    return QoeSample(
        event_ts=T0 + timedelta(seconds=offset_s),
        site_id=site_id,
        zone_id=zone_id,
        rcode=rcode,
        latency_ms=latency_ms,
        timed_out=timed_out,
    )


def window_of(thresholds, muestras, *, now=AFTER_WINDOW, **kwargs):
    """Construye una sola ventana a partir de las muestras dadas."""
    agregador = QoeAggregator(thresholds, window_seconds=60, **kwargs)
    for muestra in muestras:
        agregador.observe(muestra)
    ventanas = agregador.collect_due_windows(now)
    assert len(ventanas) == 1
    return ventanas[0]


def healthy(count: int, **kwargs) -> list[QoeSample]:
    return [sample(offset_s=i % 60, **kwargs) for i in range(count)]


# --- Carga de umbrales ------------------------------------------------------


def test_los_umbrales_del_repositorio_se_cargan(thresholds) -> None:
    assert thresholds.min_samples == 20
    assert thresholds.good_min == 85.0
    assert thresholds.warning_min == 60.0
    assert thresholds.defaults.latency_p95_ms == MetricThresholds(good=100.0, critical=500.0)
    assert thresholds.defaults.nxdomain_rate == MetricThresholds(good=0.02, critical=0.20)


def test_los_pesos_de_la_formula_suman_uno(thresholds) -> None:
    total = thresholds.weight_latency + thresholds.weight_resolution + thresholds.weight_saturation
    assert math.isclose(total, 1.0)


def test_se_rechazan_pesos_que_no_suman_uno(tmp_path: Path) -> None:
    datos = yaml.safe_load(THRESHOLDS_PATH.read_text(encoding="utf-8"))
    datos["weights"]["latency"] = 0.60
    ruta = tmp_path / "malos.yaml"
    ruta.write_text(yaml.safe_dump(datos), encoding="utf-8")
    with pytest.raises(ValueError, match="deben sumar"):
        load_thresholds(ruta)


def test_se_rechaza_warning_min_mayor_que_good_min(tmp_path: Path) -> None:
    datos = yaml.safe_load(THRESHOLDS_PATH.read_text(encoding="utf-8"))
    datos["status"]["warning_min"] = 95.0
    ruta = tmp_path / "malos.yaml"
    ruta.write_text(yaml.safe_dump(datos), encoding="utf-8")
    with pytest.raises(ValueError, match="warning_min"):
        load_thresholds(ruta)


def test_una_zona_con_override_hereda_el_resto_de_los_defaults(tmp_path: Path) -> None:
    datos = yaml.safe_load(THRESHOLDS_PATH.read_text(encoding="utf-8"))
    datos["zones"] = {"zona-sur": {"latency_p95_ms": {"good": 150.0, "critical": 600.0}}}
    ruta = tmp_path / "con_zona.yaml"
    ruta.write_text(yaml.safe_dump(datos), encoding="utf-8")

    cargados = load_thresholds(ruta)
    sur = cargados.for_zone("zona-sur")
    assert sur.latency_p95_ms == MetricThresholds(good=150.0, critical=600.0)
    assert sur.nxdomain_rate == cargados.defaults.nxdomain_rate


def test_una_zona_sin_override_usa_los_defaults(thresholds) -> None:
    assert thresholds.for_zone("zona-inexistente") is thresholds.defaults


# --- Matematica pura --------------------------------------------------------


def test_normalize_recorta_fuera_del_rango() -> None:
    limites = MetricThresholds(good=100.0, critical=500.0)
    assert normalize(50.0, limites) == 0.0
    assert normalize(100.0, limites) == 0.0
    assert normalize(500.0, limites) == 1.0
    assert normalize(9000.0, limites) == 1.0


def test_normalize_interpola_linealmente() -> None:
    limites = MetricThresholds(good=100.0, critical=500.0)
    assert normalize(300.0, limites) == pytest.approx(0.5)
    assert normalize(200.0, limites) == pytest.approx(0.25)


def test_subscore_es_el_inverso_de_normalize() -> None:
    limites = MetricThresholds(good=0.02, critical=0.20)
    assert subscore(0.02, limites) == pytest.approx(100.0)
    assert subscore(0.11, limites) == pytest.approx(50.0)
    assert subscore(0.20, limites) == pytest.approx(0.0)


def test_los_percentiles_reflejan_la_distribucion(thresholds) -> None:
    muestras = [sample(offset_s=i % 60, latency_ms=float(i + 1)) for i in range(100)]
    ventana = window_of(thresholds, muestras)
    assert ventana.latency_p50_ms == pytest.approx(50.5, abs=0.6)
    assert ventana.latency_p95_ms == pytest.approx(95.0, abs=1.0)
    assert ventana.latency_p99_ms == pytest.approx(99.0, abs=1.0)


# --- Ventanas ---------------------------------------------------------------


def test_las_ventanas_se_alinean_al_minuto(thresholds) -> None:
    agregador = QoeAggregator(thresholds, window_seconds=60)
    inicio = agregador.window_start_for(datetime(2026, 9, 10, 12, 3, 47, tzinfo=UTC))
    assert inicio == datetime(2026, 9, 10, 12, 3, 0, tzinfo=UTC)


def test_solo_se_devuelven_las_ventanas_ya_cerradas(thresholds) -> None:
    agregador = QoeAggregator(thresholds, window_seconds=60)
    for muestra in healthy(30):
        agregador.observe(muestra)
    assert agregador.collect_due_windows(T0 + timedelta(seconds=30)) == []
    assert len(agregador.collect_due_windows(T0 + timedelta(seconds=61))) == 1


def test_cerrar_dos_veces_no_duplica_ventanas(thresholds) -> None:
    agregador = QoeAggregator(thresholds, window_seconds=60)
    for muestra in healthy(30):
        agregador.observe(muestra)
    assert len(agregador.collect_due_windows(AFTER_WINDOW)) == 1
    assert agregador.collect_due_windows(AFTER_WINDOW) == []
    assert agregador.pending_windows == 0


def test_cada_sitio_y_zona_produce_su_propia_ventana(thresholds) -> None:
    agregador = QoeAggregator(thresholds, window_seconds=60)
    for muestra in healthy(30, zone_id="zona-centro"):
        agregador.observe(muestra)
    for muestra in healthy(30, zone_id="zona-sur"):
        agregador.observe(muestra)
    for muestra in healthy(30, site_id="pop-mde"):
        agregador.observe(muestra)

    ventanas = agregador.collect_due_windows(AFTER_WINDOW)
    assert len(ventanas) == 3
    assert {(v.site_id, v.zone_id) for v in ventanas} == {
        ("pop-bog", "zona-centro"),
        ("pop-bog", "zona-sur"),
        ("pop-mde", "zona-centro"),
    }


def test_flush_all_cierra_incluso_ventanas_abiertas(thresholds) -> None:
    agregador = QoeAggregator(thresholds, window_seconds=60)
    for muestra in healthy(30):
        agregador.observe(muestra)
    assert len(agregador.flush_all(T0)) == 1
    assert agregador.pending_windows == 0


def test_el_contrato_asincrono_devuelve_lo_mismo(thresholds) -> None:
    agregador = QoeAggregator(thresholds, window_seconds=60)
    for muestra in healthy(30):
        agregador.observe(muestra)
    ventanas = asyncio.run(agregador.flush_due_windows(AFTER_WINDOW))
    assert len(ventanas) == 1


# --- Buckets excluyentes ----------------------------------------------------


def test_un_timeout_no_se_cuenta_tambien_como_servfail(thresholds) -> None:
    """Sin esto, un mismo evento inflaria servfail_rate y timeout_rate a la vez."""
    muestras = healthy(80) + [
        sample(offset_s=i % 60, latency_ms=None, rcode=RCODE_TIMEOUT, timed_out=True)
        for i in range(20)
    ]
    ventana = window_of(thresholds, muestras)
    assert ventana.timeout_rate == pytest.approx(0.20)
    assert ventana.servfail_rate == pytest.approx(0.0)


def test_las_tres_tasas_de_fallo_son_excluyentes(thresholds) -> None:
    muestras = (
        healthy(40)
        + [sample(offset_s=i, rcode=RCODE_NXDOMAIN) for i in range(20)]
        + [sample(offset_s=i, rcode=RCODE_SERVFAIL) for i in range(20)]
        + [
            sample(offset_s=i, latency_ms=None, rcode=RCODE_TIMEOUT, timed_out=True)
            for i in range(20)
        ]
    )
    ventana = window_of(thresholds, muestras)
    assert ventana.nxdomain_rate == pytest.approx(0.20)
    assert ventana.servfail_rate == pytest.approx(0.20)
    assert ventana.timeout_rate == pytest.approx(0.20)
    total = ventana.nxdomain_rate + ventana.servfail_rate + ventana.timeout_rate
    assert total <= 1.0


def test_los_timeouts_no_contaminan_los_percentiles_de_latencia(thresholds) -> None:
    muestras = healthy(50, latency_ms=40.0) + [
        sample(offset_s=i, latency_ms=None, rcode=RCODE_TIMEOUT, timed_out=True)
        for i in range(50)
    ]
    ventana = window_of(thresholds, muestras)
    assert ventana.latency_p50_ms == pytest.approx(40.0)


# --- Score y estado ---------------------------------------------------------


def test_una_ventana_sana_puntua_cien(thresholds) -> None:
    ventana = window_of(thresholds, healthy(100, latency_ms=30.0))
    assert ventana.latency_score == pytest.approx(100.0)
    assert ventana.resolution_score == pytest.approx(100.0)
    assert ventana.saturation_score == pytest.approx(100.0)
    assert ventana.qoe_score == pytest.approx(100.0)
    assert ventana.status == STATUS_GOOD


def test_el_score_final_aplica_los_pesos_de_la_spec(thresholds) -> None:
    """Recalcula 0.45L + 0.30R + 0.25S a mano sobre la ventana producida."""
    muestras = healthy(70, latency_ms=300.0) + [
        sample(offset_s=i, latency_ms=300.0, rcode=RCODE_NXDOMAIN) for i in range(30)
    ]
    ventana = window_of(thresholds, muestras)
    esperado = (
        0.45 * ventana.latency_score
        + 0.30 * ventana.resolution_score
        + 0.25 * ventana.saturation_score
    )
    assert ventana.qoe_score == pytest.approx(esperado, abs=0.01)


def test_la_latencia_critica_hunde_su_subscore(thresholds) -> None:
    ventana = window_of(thresholds, healthy(100, latency_ms=600.0))
    assert ventana.latency_score == pytest.approx(0.0)
    assert ventana.status == STATUS_CRITICAL
    assert ventana.primary_cause == CAUSE_LATENCY


def test_pocas_muestras_no_se_marcan_como_falla(thresholds) -> None:
    ventana = window_of(thresholds, healthy(10, latency_ms=900.0))
    assert ventana.sample_count == 10
    assert ventana.status == STATUS_INSUFFICIENT_DATA
    assert ventana.primary_cause == CAUSE_INSUFFICIENT


def test_el_minimo_de_muestras_es_inclusivo(thresholds) -> None:
    ventana = window_of(thresholds, healthy(20))
    assert ventana.status != STATUS_INSUFFICIENT_DATA


def test_los_estados_respetan_sus_umbrales(thresholds) -> None:
    muestras = healthy(100, latency_ms=30.0)
    ventana = window_of(thresholds, muestras)
    assert ventana.qoe_score >= thresholds.good_min
    assert ventana.status == STATUS_GOOD

    degradada = window_of(thresholds, healthy(100, latency_ms=30.0, rcode=RCODE_NXDOMAIN))
    assert thresholds.warning_min <= degradada.qoe_score < thresholds.good_min
    assert degradada.status == STATUS_WARNING


# --- Causa principal --------------------------------------------------------


def test_la_causa_es_el_nxdomain_cuando_domina_ese_fallo(thresholds) -> None:
    ventana = window_of(thresholds, healthy(100, rcode=RCODE_NXDOMAIN))
    assert ventana.resolution_score == pytest.approx(0.0)
    assert ventana.primary_cause == CAUSE_NXDOMAIN


def test_la_causa_es_la_saturacion_cuando_dominan_los_servfail(thresholds) -> None:
    muestras = healthy(70) + [sample(offset_s=i, rcode=RCODE_SERVFAIL) for i in range(30)]
    ventana = window_of(thresholds, muestras)
    assert ventana.saturation_score == pytest.approx(0.0)
    assert ventana.primary_cause == CAUSE_SATURATION


def test_sin_ninguna_latencia_medida_no_se_culpa_a_la_latencia(thresholds) -> None:
    """Todo timeout: el problema es que nada resolvio, no que fuera lento."""
    muestras = [
        sample(offset_s=i % 60, latency_ms=None, rcode=RCODE_TIMEOUT, timed_out=True)
        for i in range(100)
    ]
    ventana = window_of(thresholds, muestras)
    assert ventana.timeout_rate == pytest.approx(1.0)
    assert ventana.primary_cause == CAUSE_SATURATION
    assert ventana.status == STATUS_CRITICAL


# --- Salida -----------------------------------------------------------------


def test_la_ventana_reporta_version_de_calculo_y_marca_de_tiempo(thresholds) -> None:
    ventana = window_of(thresholds, healthy(30))
    assert ventana.calculation_version == thresholds.version
    assert ventana.window_start == T0
    assert ventana.updated_at.tzinfo is not None


def test_todas_las_tasas_y_scores_estan_en_rango(thresholds) -> None:
    casos = [
        healthy(100, latency_ms=30.0),
        healthy(100, latency_ms=5000.0),
        healthy(100, rcode=RCODE_NXDOMAIN),
        [
            sample(offset_s=i % 60, latency_ms=None, rcode=RCODE_TIMEOUT, timed_out=True)
            for i in range(100)
        ],
    ]
    for muestras in casos:
        ventana = window_of(thresholds, muestras)
        for tasa in (ventana.nxdomain_rate, ventana.servfail_rate, ventana.timeout_rate):
            assert 0.0 <= tasa <= 1.0
        assert 0.0 <= ventana.saturation_index <= 1.0
        for score in (
            ventana.latency_score,
            ventana.resolution_score,
            ventana.saturation_score,
            ventana.qoe_score,
        ):
            assert 0.0 <= score <= 100.0
