"""Productor sintético de tráfico DNS (spec sección 12).

Uso típico, desde el host con el Compose levantado:

    python -m simulator.main --scenario mixed_demo --seed 42

Varias zonas a la vez, para poblar la matriz sitio × zona del dashboard:

    python -m simulator.main --scenario mixed_demo --zone zona-centro,zona-sur

Sin Kafka, para inspeccionar lo que se publicaría:

    python -m simulator.main --scenario dga_burst --duration 5 --dry-run

Tiempo real: cada evento se emite en su segundo y lleva `event_ts` = ahora.
El consumer (A5) descarta eventos con más de `clock_skew_tolerance_seconds`
(300 s por defecto) de diferencia con su reloj, así que estampar un escenario
entero por adelantado mandaría sus últimos minutos directo a la DLQ.

Seed y run_id: la seed fija el CONTENIDO del escenario (dominios, tiempos,
fallos); el `run_id` fija la IDENTIDAD de cada corrida (los `event_id`). Por
defecto cada ejecución genera un `run_id` nuevo. Si los `event_id` salieran
solo de la seed, repetir una corrida (por ejemplo, el ensayo antes de grabar
el video) produciría los mismos IDs, y el `PredictionService` los descartaría
como duplicados (spec sección 14): la segunda corrida no detectaría nada. Para
repetir una corrida idéntica, IDs incluidos, se pasa el mismo `--run-id`.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import sys
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from app.domain.schemas import NormalizedDnsEvent
from simulator.profiles import DEFAULT_ZONE, SITES, get_profile
from simulator.scenarios import SCENARIOS, ScenarioContext, SyntheticQuery, list_scenarios

__all__ = [
    "PlannedEvent",
    "plan",
    "new_run_id",
    "to_event",
    "ground_truth_labels",
    "publish",
    "main",
]

# El simulador corre en el host: usa el listener de loopback de compose.yaml.
DEFAULT_BOOTSTRAP = "localhost:29092"
BOOTSTRAP_ENV = "SENTINEL_KAFKA__BOOTSTRAP_SERVERS"
# Cada cuántos eventos se esperan las confirmaciones de Kafka.
FLUSH_EVERY = 500


@dataclass(frozen=True, slots=True)
class PlannedEvent:
    """Una consulta del escenario con su identidad ya asignada."""

    event_id: uuid.UUID
    query: SyntheticQuery
    run_id: str = ""


class EventSink(Protocol):
    """Destino de los eventos. `KafkaEventProducer` lo implementa."""

    async def publish_event(self, event: NormalizedDnsEvent) -> None: ...

    async def publish_ground_truth(self, event_id: str, labels: dict[str, Any]) -> None: ...

    async def flush(self) -> int: ...


# ---------------------------------------------------------------------------
# Planificación: determinista, sin reloj ni red
# ---------------------------------------------------------------------------


def plan(
    scenario: str,
    *,
    sites: Sequence[str],
    zones: Sequence[str],
    rate_per_s: float,
    duration_s: float,
    seed: int,
    run_id: str | None = None,
) -> list[PlannedEvent]:
    """Genera la secuencia completa de eventos, ordenada por tiempo.

    Cada combinación sitio/zona usa su propia semilla derivada. Si todas
    compartieran la misma, repetirían los mismos `client_hash` y los mismos
    dominios de beaconing, y el detector vería una sola campaña con intervalos
    mezclados en vez de una por zona.

    Sin `run_id` se genera uno nuevo: dos llamadas producen el mismo contenido
    con `event_id` distintos (ver el docstring del módulo).
    """
    run_id = run_id or new_run_id()
    spec = SCENARIOS[scenario]
    consultas: list[SyntheticQuery] = []
    for site in sites:
        for zone in zones:
            ctx = ScenarioContext(
                rng=random.Random(f"{seed}:{site}:{zone}"),
                profile=get_profile(zone),
                site_id=site,
                rate_per_s=rate_per_s,
                duration_s=duration_s,
            )
            consultas.extend(spec.build(ctx))
    consultas.sort(key=lambda q: q.offset_s)

    # Los IDs salen de un generador aparte para no alterar la secuencia del
    # escenario, y dependen del run_id para que cada corrida tenga los suyos.
    ids = random.Random(f"{seed}:{run_id}:event-ids")
    return [
        PlannedEvent(uuid.UUID(int=ids.getrandbits(128), version=4), q, run_id) for q in consultas
    ]


def new_run_id() -> str:
    """Identificador corto y único para una corrida del simulador."""
    return uuid.uuid4().hex[:12]


def resolver_id_for(site_id: str) -> str:
    return f"rslv-{site_id}-01"


def to_event(planned: PlannedEvent, *, now: datetime) -> NormalizedDnsEvent:
    """Traduce una consulta sintética al contrato del dominio.

    No incluye ningún dato de ground truth: eso viaja por otro topic.
    """
    q = planned.query
    return NormalizedDnsEvent(
        event_id=planned.event_id,
        event_ts=now,
        observed_at=now,
        site_id=q.site_id,
        zone_id=q.zone_id,
        resolver_id=resolver_id_for(q.site_id),
        client_hash=q.client_hash,
        qname=q.qname,
        qtype=q.qtype,
        rcode=q.rcode,
        latency_ms=q.latency_ms,
        response_bytes=q.response_bytes,
        timed_out=q.timed_out,
        synthetic=True,
    )


def ground_truth_labels(planned: PlannedEvent) -> dict[str, Any]:
    truth = planned.query.ground_truth
    return {
        "run_id": planned.run_id,
        "scenario": truth.scenario,
        "threat_type": truth.threat_type,
        "target_brand": truth.target_brand,
        "technique": truth.technique,
        "site_id": planned.query.site_id,
        "zone_id": planned.query.zone_id,
    }


# ---------------------------------------------------------------------------
# Emisión
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class PublishStats:
    published: int = 0
    confirmed: int = 0


async def publish(
    planned: Sequence[PlannedEvent],
    sink: EventSink,
    *,
    speed: float = 1.0,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    on_progress: Callable[[PublishStats], None] | None = None,
) -> PublishStats:
    """Emite los eventos respetando sus offsets, divididos por `speed`."""
    if speed <= 0:
        raise ValueError("speed debe ser positivo")
    stats = PublishStats()
    start = time.monotonic()
    for index, item in enumerate(planned, start=1):
        delay = start + item.query.offset_s / speed - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)
        event = to_event(item, now=clock())
        await sink.publish_event(event)
        await sink.publish_ground_truth(str(item.event_id), ground_truth_labels(item))
        stats.published += 1
        if index % FLUSH_EVERY == 0:
            stats.confirmed += await sink.flush()
            if on_progress is not None:
                on_progress(stats)
    stats.confirmed += await sink.flush()
    return stats


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _csv(value: str) -> list[str]:
    items = [item.strip() for item in value.split(",") if item.strip()]
    if not items:
        raise argparse.ArgumentTypeError("se esperaba al menos un valor")
    return items


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m simulator.main",
        description="Publica tráfico DNS sintético en Kafka.",
    )
    parser.add_argument("--scenario", default="mixed_demo", choices=list_scenarios())
    parser.add_argument("--rate", type=float, default=None, help="eventos/s por sitio y zona")
    parser.add_argument("--duration", type=float, default=None, help="segundos")
    parser.add_argument("--seed", type=int, default=42, help="fija el contenido del escenario")
    parser.add_argument(
        "--run-id",
        default=None,
        help=(
            "identidad de la corrida (define los event_id). Por defecto se genera "
            "uno nuevo; pasar uno anterior repite la corrida exacta"
        ),
    )
    parser.add_argument("--site", type=_csv, default=[SITES[0]], help="uno o varios, con comas")
    parser.add_argument("--zone", type=_csv, default=[DEFAULT_ZONE], help="una o varias, con comas")
    parser.add_argument(
        "--bootstrap",
        default=os.environ.get(BOOTSTRAP_ENV, DEFAULT_BOOTSTRAP),
        help=f"broker Kafka (por defecto {DEFAULT_BOOTSTRAP} o ${BOOTSTRAP_ENV})",
    )
    parser.add_argument(
        "--speed",
        type=float,
        default=1.0,
        help=(
            "acelera la emisión. Solo para pruebas de humo: comprime los intervalos, "
            "así que beaconing deja de detectarse y las ventanas de QoE se mezclan"
        ),
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="imprime los eventos en vez de publicarlos"
    )
    return parser


def _resolve(args: argparse.Namespace) -> tuple[float, float]:
    spec = SCENARIOS[args.scenario]
    rate = args.rate if args.rate is not None else spec.default_rate_per_s
    duration = args.duration if args.duration is not None else spec.default_duration_s
    if rate <= 0 or duration <= 0:
        raise SystemExit("--rate y --duration deben ser positivos")
    return rate, duration


def _dry_run(planned: Sequence[PlannedEvent]) -> None:
    now = datetime.now(UTC)
    for item in planned:
        linea = {
            "offset_s": item.query.offset_s,
            "event": json.loads(to_event(item, now=now).model_dump_json()),
            "ground_truth": ground_truth_labels(item),
        }
        print(json.dumps(linea, ensure_ascii=False))


async def _run_kafka(args: argparse.Namespace, planned: Sequence[PlannedEvent]) -> None:
    # Import diferido: --dry-run y los tests no necesitan aiokafka.
    from app.infrastructure.kafka.producer import KafkaEventProducer

    total = len(planned)

    def progreso(stats: PublishStats) -> None:
        print(f"  {stats.published}/{total} publicados", file=sys.stderr)

    async with KafkaEventProducer(args.bootstrap) as producer:
        stats = await publish(planned, producer, speed=args.speed, on_progress=progreso)
    print(
        f"listo: {stats.published} eventos publicados, {stats.confirmed} mensajes "
        "confirmados por Kafka (eventos + ground truth)",
        file=sys.stderr,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    rate, duration = _resolve(args)
    run_id = args.run_id or new_run_id()
    planned = plan(
        args.scenario,
        sites=args.site,
        zones=args.zone,
        rate_per_s=rate,
        duration_s=duration,
        seed=args.seed,
        run_id=run_id,
    )
    if args.dry_run:
        _dry_run(planned)
        return 0

    combos = len(args.site) * len(args.zone)
    print(
        f"escenario={args.scenario} seed={args.seed} run_id={run_id} sitios×zonas={combos} "
        f"eventos={len(planned)} duracion≈{duration / args.speed:.0f}s "
        f"broker={args.bootstrap}",
        file=sys.stderr,
    )
    try:
        asyncio.run(_run_kafka(args, planned))
    except KeyboardInterrupt:
        print("interrumpido", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
