"""Tests del publicador del simulador (C1): `simulator/main.py`.

El test central reproduce lo que hace `KafkaDnsConsumer` (A5) con cada mensaje:
`json.loads` sobre los bytes y después `NormalizedDnsEvent.model_validate`. Si
un evento no pasara ese camino, el consumer lo mandaría a la DLQ y nunca
llegaría al detector.

No requieren Kafka: la emisión se prueba contra un destino falso.
"""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.domain.schemas import NormalizedDnsEvent
from simulator.main import (
    PlannedEvent,
    ground_truth_labels,
    main,
    plan,
    publish,
    to_event,
)
from simulator.scenarios import RCODE_TIMEOUT, list_scenarios

# Tolerancia de reloj por defecto del consumer (app/core/config.py).
CLOCK_SKEW_TOLERANCE_S = 300
GROUND_TRUTH_FIELDS = {"scenario", "threat_type", "target_brand", "technique"}


def planned(
    scenario: str = "mixed_demo",
    *,
    seed: int = 42,
    sites: tuple[str, ...] = ("pop-bog",),
    zones: tuple[str, ...] = ("zona-centro",),
    duration_s: float = 60.0,
    run_id: str | None = None,
) -> list[PlannedEvent]:
    return plan(
        scenario,
        sites=sites,
        zones=zones,
        rate_per_s=20.0,
        duration_s=duration_s,
        seed=seed,
        run_id=run_id,
    )


def as_consumer_would(payload: bytes) -> NormalizedDnsEvent:
    """Mismo decode que `KafkaDnsConsumer._decode`."""
    return NormalizedDnsEvent.model_validate(json.loads(payload.decode("utf-8")))


class FakeSink:
    """Registra lo publicado, serializado igual que el productor real."""

    def __init__(self) -> None:
        self.events: list[bytes] = []
        self.ground_truth: list[dict[str, Any]] = []
        self.flushes = 0
        self._pending = 0

    async def publish_event(self, event: NormalizedDnsEvent) -> None:
        self.events.append(event.model_dump_json().encode("utf-8"))
        self._pending += 1

    async def publish_ground_truth(self, event_id: str, labels: dict[str, Any]) -> None:
        self.ground_truth.append({"event_id": event_id, **labels})
        self._pending += 1

    async def flush(self) -> int:
        self.flushes += 1
        confirmed, self._pending = self._pending, 0
        return confirmed


# --- Contrato con el consumer -----------------------------------------------


@pytest.mark.parametrize("scenario", list_scenarios())
def test_cada_evento_pasa_el_decode_del_consumer(scenario: str) -> None:
    now = datetime.now(UTC)
    duracion = 60.0 if scenario == "mixed_demo" else 20.0
    for item in planned(scenario, duration_s=duracion):
        payload = to_event(item, now=now).model_dump_json().encode("utf-8")
        evento = as_consumer_would(payload)
        assert evento.event_id == item.event_id
        assert evento.synthetic is True


def test_el_evento_no_filtra_el_ground_truth() -> None:
    """El detector no debe poder ver la respuesta (spec sección 12)."""
    now = datetime.now(UTC)
    for item in planned():
        crudo = json.loads(to_event(item, now=now).model_dump_json())
        assert GROUND_TRUTH_FIELDS.isdisjoint(crudo), crudo.keys()


def test_los_timeouts_conservan_la_convencion_acordada() -> None:
    now = datetime.now(UTC)
    timeouts = [
        to_event(item, now=now) for item in planned("resolver_saturation") if item.query.timed_out
    ]
    assert timeouts, "el escenario deberia producir timeouts"
    for evento in timeouts:
        assert evento.rcode == RCODE_TIMEOUT
        assert evento.timed_out is True
        assert evento.latency_ms is None


def test_el_qname_llega_normalizado_sin_cambios() -> None:
    """Si la normalización del contrato alterara un dominio, el ground truth ya
    no coincidiría con lo que ve el detector."""
    now = datetime.now(UTC)
    for item in planned():
        assert to_event(item, now=now).qname == item.query.qname


# --- Planificación ----------------------------------------------------------


def test_la_misma_seed_y_el_mismo_run_id_repiten_la_corrida_exacta() -> None:
    assert planned(seed=7, run_id="ensayo") == planned(seed=7, run_id="ensayo")


def test_seeds_distintas_producen_eventos_distintos() -> None:
    assert planned(seed=1) != planned(seed=2)


def test_sin_run_id_cada_corrida_repite_el_contenido_con_ids_nuevos() -> None:
    """Repetir la demo (el ensayo antes del video) no debe producir duplicados:
    el PredictionService descarta cualquier event_id que ya vio (spec sección 14)."""
    primera = planned(seed=42)
    segunda = planned(seed=42)
    assert [p.query for p in primera] == [p.query for p in segunda]
    assert {p.event_id for p in primera}.isdisjoint(p.event_id for p in segunda)


def test_dos_simuladores_con_la_misma_seed_no_comparten_ids() -> None:
    """Regresión de la prueba E2E: centro y sur en paralelo, ambos con seed 42,
    repetían los mismos event_id y el detector descartaba casi todo sur."""
    centro = planned("normal", zones=("zona-centro",), duration_s=30.0)
    sur = planned("zone_latency", zones=("zona-sur",), duration_s=30.0)
    assert {p.event_id for p in centro}.isdisjoint(p.event_id for p in sur)


def test_cada_evento_lleva_el_run_id_de_su_corrida() -> None:
    eventos = planned(run_id="corrida-1")
    assert {p.run_id for p in eventos} == {"corrida-1"}
    assert all(ground_truth_labels(p)["run_id"] == "corrida-1" for p in eventos)


def test_los_event_id_son_unicos() -> None:
    eventos = planned(sites=("pop-bog", "pop-mde"), zones=("zona-centro", "zona-sur"))
    assert len({item.event_id for item in eventos}) == len(eventos)


def test_la_secuencia_esta_ordenada_por_tiempo() -> None:
    eventos = planned(zones=("zona-centro", "zona-sur", "zona-norte"))
    offsets = [item.query.offset_s for item in eventos]
    assert offsets == sorted(offsets)


def test_cada_zona_tiene_clientes_propios() -> None:
    """Si compartieran client_hash, el detector mezclaría campañas de zonas
    distintas y el jitter de beaconing dejaría de ser bajo."""
    clientes: dict[str, set[str]] = defaultdict(set)
    for item in planned(zones=("zona-centro", "zona-sur")):
        clientes[item.query.zone_id].add(item.query.client_hash)
    assert clientes["zona-centro"].isdisjoint(clientes["zona-sur"])


def test_cada_zona_tiene_su_propia_campana_de_beaconing() -> None:
    dominios: dict[str, set[str]] = defaultdict(set)
    for item in planned("beaconing", zones=("zona-centro", "zona-sur")):
        if item.query.ground_truth.threat_type == "beaconing":
            dominios[item.query.zone_id].add(item.query.qname)
    assert dominios["zona-centro"]
    assert dominios["zona-centro"].isdisjoint(dominios["zona-sur"])


def test_el_ground_truth_corresponde_a_su_evento() -> None:
    for item in planned():
        etiquetas = ground_truth_labels(item)
        assert etiquetas["scenario"] == item.query.ground_truth.scenario
        assert etiquetas["threat_type"] == item.query.ground_truth.threat_type
        assert etiquetas["zone_id"] == item.query.zone_id


# --- Emisión ----------------------------------------------------------------


def test_publish_emite_cada_evento_con_su_ground_truth() -> None:
    eventos = planned("dga_burst", duration_s=10.0)
    destino = FakeSink()
    stats = asyncio.run(publish(eventos, destino, speed=1e6))

    assert stats.published == len(eventos)
    assert len(destino.events) == len(eventos)
    assert len(destino.ground_truth) == len(eventos)
    assert stats.confirmed == 2 * len(eventos)

    publicados = {as_consumer_would(p).event_id for p in destino.events}
    etiquetados = {gt["event_id"] for gt in destino.ground_truth}
    assert publicados == {item.event_id for item in eventos}
    assert etiquetados == {str(e) for e in publicados}


def test_publish_respeta_el_orden_de_la_secuencia() -> None:
    eventos = planned(duration_s=20.0)
    destino = FakeSink()
    asyncio.run(publish(eventos, destino, speed=1e6))
    ids = [as_consumer_would(p).event_id for p in destino.events]
    assert ids == [item.event_id for item in eventos]


def test_los_timestamps_caen_dentro_de_la_tolerancia_del_consumer() -> None:
    """Estampar un escenario por adelantado mandaría sus últimos minutos a la DLQ."""
    eventos = planned(duration_s=10.0)
    destino = FakeSink()
    asyncio.run(publish(eventos, destino, speed=1e6))
    ahora = datetime.now(UTC)
    for payload in destino.events:
        evento = as_consumer_would(payload)
        assert abs((evento.event_ts - ahora).total_seconds()) <= CLOCK_SKEW_TOLERANCE_S


def test_publish_usa_el_reloj_real_al_emitir() -> None:
    marcas = iter(
        datetime(2026, 9, 10, 12, 0, tzinfo=UTC) + timedelta(seconds=i) for i in range(10_000)
    )
    eventos = planned(duration_s=5.0)
    destino = FakeSink()
    asyncio.run(publish(eventos, destino, speed=1e6, clock=lambda: next(marcas)))
    primero = as_consumer_would(destino.events[0])
    ultimo = as_consumer_would(destino.events[-1])
    assert primero.event_ts < ultimo.event_ts


def test_publish_rechaza_una_velocidad_invalida() -> None:
    with pytest.raises(ValueError, match="speed"):
        asyncio.run(publish([], FakeSink(), speed=0))


# --- CLI --------------------------------------------------------------------


def test_dry_run_imprime_un_evento_valido_por_linea(capsys: pytest.CaptureFixture[str]) -> None:
    codigo = main(["--scenario", "tunneling", "--duration", "3", "--dry-run"])
    assert codigo == 0

    lineas = capsys.readouterr().out.strip().splitlines()
    esperados = planned("tunneling", duration_s=3.0)
    assert len(lineas) == len(esperados)
    for linea in lineas:
        registro = json.loads(linea)
        evento = NormalizedDnsEvent.model_validate(registro["event"])
        assert str(evento.event_id)
        assert GROUND_TRUTH_FIELDS <= registro["ground_truth"].keys()


def test_la_cli_acepta_varias_zonas_separadas_por_comas(
    capsys: pytest.CaptureFixture[str],
) -> None:
    main(["--scenario", "normal", "--duration", "2", "--zone", "zona-centro,zona-sur", "--dry-run"])
    zonas = {
        json.loads(linea)["event"]["zone_id"] for linea in capsys.readouterr().out.splitlines()
    }
    assert zonas == {"zona-centro", "zona-sur"}


def test_la_cli_rechaza_un_escenario_inexistente() -> None:
    with pytest.raises(SystemExit):
        main(["--scenario", "no-existe", "--dry-run"])


def test_la_cli_genera_un_run_id_nuevo_en_cada_ejecucion(
    capsys: pytest.CaptureFixture[str],
) -> None:
    def ids_de_una_corrida() -> set[str]:
        main(["--scenario", "normal", "--duration", "2", "--dry-run"])
        lineas = capsys.readouterr().out.splitlines()
        return {json.loads(linea)["event"]["event_id"] for linea in lineas}

    assert ids_de_una_corrida().isdisjoint(ids_de_una_corrida())


def test_la_cli_con_run_id_explicito_es_reproducible(
    capsys: pytest.CaptureFixture[str],
) -> None:
    def ids_de_una_corrida() -> list[str]:
        main(["--scenario", "normal", "--duration", "2", "--run-id", "video", "--dry-run"])
        lineas = capsys.readouterr().out.splitlines()
        return [json.loads(linea)["event"]["event_id"] for linea in lineas]

    assert ids_de_una_corrida() == ids_de_una_corrida()
