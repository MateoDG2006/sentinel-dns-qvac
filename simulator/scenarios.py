"""Catalogo de escenarios deterministas para el productor sintetico.

Cada escenario produce una lista de :class:`SyntheticQuery`, una representacion
intermedia propia del simulador. ``simulator.main`` la traduce despues a
``NormalizedDnsEvent``; asi este modulo no depende de los contratos del dominio
y puede evolucionar sin tocar el frente A.

Convenciones de este simulador (spec seccion 12):

- Todos los eventos son sinteticos. El ground truth viaja aparte y se publica
  solo en el topic de evaluacion, nunca dentro del evento analizado.
- ``rcode`` y ``timed_out`` son coherentes entre si y mutuamente excluyentes:
  un timeout se emite como ``rcode="TIMEOUT"`` con ``timed_out=True`` y sin
  latencia. Esto evita contar el mismo evento como SERVFAIL y como timeout al
  calcular QoE.
- Misma seed + mismos parametros => misma secuencia de eventos.
"""

import random
from collections.abc import Callable
from dataclasses import dataclass, replace

from simulator import domains
from simulator.profiles import ZoneProfile

__all__ = [
    "GroundTruth",
    "SyntheticQuery",
    "ScenarioContext",
    "ScenarioSpec",
    "SCENARIOS",
    "get_scenario",
    "list_scenarios",
    "RCODE_TIMEOUT",
]

RCODE_NOERROR = "NOERROR"
RCODE_NXDOMAIN = "NXDOMAIN"
RCODE_SERVFAIL = "SERVFAIL"
# Valor centinela: un timeout no tiene rcode real porque nunca hubo respuesta.
RCODE_TIMEOUT = "TIMEOUT"

_NORMAL_QTYPES = ("A", "AAAA", "HTTPS")
_NORMAL_QTYPE_WEIGHTS = (70, 25, 5)


@dataclass(frozen=True, slots=True)
class GroundTruth:
    """Etiqueta real del evento. Nunca se incluye en el evento analizado."""

    scenario: str
    threat_type: str = "none"
    target_brand: str | None = None
    technique: str | None = None


@dataclass(frozen=True, slots=True)
class SyntheticQuery:
    """Una consulta DNS sintetica, previa a la traduccion al schema del dominio."""

    offset_s: float
    site_id: str
    zone_id: str
    client_hash: str
    qname: str
    qtype: str
    rcode: str
    latency_ms: float | None
    response_bytes: int | None
    timed_out: bool
    ground_truth: GroundTruth


@dataclass(frozen=True, slots=True)
class ScenarioContext:
    """Parametros de una corrida de escenario."""

    rng: random.Random
    profile: ZoneProfile
    site_id: str
    rate_per_s: float
    duration_s: float
    start_offset_s: float = 0.0

    @property
    def zone_id(self) -> str:
        return self.profile.zone_id


ScenarioBuilder = Callable[[ScenarioContext], list[SyntheticQuery]]


@dataclass(frozen=True, slots=True)
class ScenarioSpec:
    """Metadatos y constructor de un escenario."""

    name: str
    description: str
    build: ScenarioBuilder
    default_rate_per_s: float = 20.0
    default_duration_s: float = 60.0


# ---------------------------------------------------------------------------
# Utilidades comunes
# ---------------------------------------------------------------------------


def _client_pool(rng: random.Random, size: int) -> list[str]:
    """Identificadores de cliente anonimizados y estables dentro de la corrida."""
    return [f"{rng.getrandbits(64):016x}" for _ in range(size)]


def _arrival_times(ctx: ScenarioContext) -> list[float]:
    """Llegadas de un proceso de Poisson dentro de la ventana del escenario."""
    end = ctx.start_offset_s + ctx.duration_s
    times: list[float] = []
    current = ctx.start_offset_s
    while True:
        current += ctx.rng.expovariate(ctx.rate_per_s)
        if current >= end:
            return times
        times.append(current)


def _normal_qtype(rng: random.Random) -> str:
    return rng.choices(_NORMAL_QTYPES, weights=_NORMAL_QTYPE_WEIGHTS, k=1)[0]


def _outcome(
    ctx: ScenarioContext,
    *,
    nxdomain_rate: float | None = None,
    servfail_rate: float | None = None,
    timeout_rate: float | None = None,
    latency_factor: float = 1.0,
) -> tuple[str, float | None, int | None, bool]:
    """Sortea (rcode, latencia, bytes, timed_out) segun el perfil y sus overrides.

    Los tres buckets de fallo son excluyentes: un evento cae en timeout, en
    SERVFAIL, en NXDOMAIN o en NOERROR, nunca en dos a la vez.
    """
    profile = ctx.profile
    rng = ctx.rng
    p_timeout = profile.timeout_rate if timeout_rate is None else timeout_rate
    p_servfail = profile.servfail_rate if servfail_rate is None else servfail_rate
    p_nxdomain = profile.nxdomain_rate if nxdomain_rate is None else nxdomain_rate

    roll = rng.random()
    if roll < p_timeout:
        return RCODE_TIMEOUT, None, None, True
    roll -= p_timeout
    latency = round(profile.sample_latency_ms(rng) * latency_factor, 2)
    if roll < p_servfail:
        return RCODE_SERVFAIL, latency, None, False
    roll -= p_servfail
    if roll < p_nxdomain:
        return RCODE_NXDOMAIN, latency, rng.randint(40, 90), False
    return RCODE_NOERROR, latency, profile.sample_response_bytes(rng), False


def _query(
    ctx: ScenarioContext,
    *,
    offset_s: float,
    client_hash: str,
    qname: str,
    qtype: str,
    ground_truth: GroundTruth,
    nxdomain_rate: float | None = None,
    servfail_rate: float | None = None,
    timeout_rate: float | None = None,
    latency_factor: float = 1.0,
    response_bytes: int | None = None,
) -> SyntheticQuery:
    """Construye una consulta aplicando el sorteo de resultado del perfil."""
    rcode, latency, sampled_bytes, timed_out = _outcome(
        ctx,
        nxdomain_rate=nxdomain_rate,
        servfail_rate=servfail_rate,
        timeout_rate=timeout_rate,
        latency_factor=latency_factor,
    )
    payload_bytes = sampled_bytes if timed_out or response_bytes is None else response_bytes
    return SyntheticQuery(
        offset_s=round(offset_s, 3),
        site_id=ctx.site_id,
        zone_id=ctx.zone_id,
        client_hash=client_hash,
        qname=qname,
        qtype=qtype,
        rcode=rcode,
        latency_ms=latency,
        response_bytes=payload_bytes,
        timed_out=timed_out,
        ground_truth=ground_truth,
    )


def _background(ctx: ScenarioContext, scenario: str, *, clients: int = 40) -> list[SyntheticQuery]:
    """Trafico de fondo sano, usado como relleno por los escenarios de amenaza."""
    pool = _client_pool(ctx.rng, clients)
    truth = GroundTruth(scenario=scenario)
    return [
        _query(
            ctx,
            offset_s=offset,
            client_hash=ctx.rng.choice(pool),
            qname=domains.normal_domain(ctx.rng),
            qtype=_normal_qtype(ctx.rng),
            ground_truth=truth,
        )
        for offset in _arrival_times(ctx)
    ]


def _sorted(queries: list[SyntheticQuery]) -> list[SyntheticQuery]:
    return sorted(queries, key=lambda q: q.offset_s)


# ---------------------------------------------------------------------------
# Escenarios
# ---------------------------------------------------------------------------


def _build_normal(ctx: ScenarioContext) -> list[SyntheticQuery]:
    return _sorted(_background(ctx, "normal"))


def _build_dga_burst(ctx: ScenarioContext) -> list[SyntheticQuery]:
    """Rafaga de dominios de alta entropia; la mayoria resuelve NXDOMAIN."""
    infected = _client_pool(ctx.rng, 3)
    truth = GroundTruth(scenario="dga_burst", threat_type="dga")
    malicious = [
        _query(
            ctx,
            offset_s=offset,
            client_hash=ctx.rng.choice(infected),
            qname=domains.dga_domain(ctx.rng),
            qtype="A",
            ground_truth=truth,
            # Los dominios generados por DGA rara vez estan registrados.
            nxdomain_rate=0.75,
            servfail_rate=0.02,
            timeout_rate=0.01,
        )
        for offset in _arrival_times(replace(ctx, rate_per_s=ctx.rate_per_s * 0.6))
    ]
    background = _background(replace(ctx, rate_per_s=ctx.rate_per_s * 0.4), "dga_burst")
    return _sorted(malicious + background)


def _build_typosquatting(ctx: ScenarioContext) -> list[SyntheticQuery]:
    """Variantes enganosas de marcas ficticias, que si resuelven."""
    victims = _client_pool(ctx.rng, 12)
    malicious: list[SyntheticQuery] = []
    for offset in _arrival_times(replace(ctx, rate_per_s=ctx.rate_per_s * 0.35)):
        typo = domains.typosquat_domain(ctx.rng)
        malicious.append(
            _query(
                ctx,
                offset_s=offset,
                client_hash=ctx.rng.choice(victims),
                qname=typo.domain,
                qtype="A",
                ground_truth=GroundTruth(
                    scenario="typosquatting",
                    threat_type="typosquatting",
                    target_brand=typo.target_brand,
                    technique=typo.technique,
                ),
                nxdomain_rate=0.05,
            )
        )
    background = _background(replace(ctx, rate_per_s=ctx.rate_per_s * 0.65), "typosquatting")
    return _sorted(malicious + background)


def _build_tunneling(ctx: ScenarioContext) -> list[SyntheticQuery]:
    """Pocos clientes con consultas TXT de subdominio largo y unico."""
    tunnel_clients = _client_pool(ctx.rng, 2)
    base = f"tunnel.{domains.synthetic_tld(ctx.rng)}"
    truth = GroundTruth(scenario="tunneling", threat_type="dns_tunneling")
    malicious = [
        _query(
            ctx,
            offset_s=offset,
            client_hash=ctx.rng.choice(tunnel_clients),
            qname=domains.tunneling_qname(ctx.rng, base),
            qtype="TXT",
            ground_truth=truth,
            nxdomain_rate=0.01,
            # Las respuestas TXT del tunel son grandes.
            response_bytes=ctx.rng.randint(280, 512),
        )
        # Frecuencia elevada: el tunel domina el volumen del escenario.
        for offset in _arrival_times(replace(ctx, rate_per_s=ctx.rate_per_s * 1.5))
    ]
    background = _background(replace(ctx, rate_per_s=ctx.rate_per_s * 0.5), "tunneling")
    return _sorted(malicious + background)


def _build_beaconing(ctx: ScenarioContext) -> list[SyntheticQuery]:
    """Consultas periodicas al mismo dominio con jitter bajo."""
    rng = ctx.rng
    queries: list[SyntheticQuery] = []
    end = ctx.start_offset_s + ctx.duration_s
    for client in _client_pool(rng, 4):
        domain = domains.beaconing_domain(rng)
        # Intervalos cortos para que una ventana de 60 s contenga suficientes
        # repeticiones como para que la heuristica mida periodicidad y jitter.
        interval = float(rng.choice((5, 8, 12)))
        jitter = interval * 0.03
        truth = GroundTruth(scenario="beaconing", threat_type="beaconing")
        tick = ctx.start_offset_s + rng.uniform(0.0, interval)
        while tick < end:
            queries.append(
                _query(
                    ctx,
                    offset_s=tick,
                    client_hash=client,
                    qname=domain,
                    qtype="A",
                    ground_truth=truth,
                    nxdomain_rate=0.02,
                )
            )
            tick += interval + rng.uniform(-jitter, jitter)
    queries.extend(_background(replace(ctx, rate_per_s=ctx.rate_per_s * 0.8), "beaconing"))
    return _sorted(queries)


def _build_zone_latency(ctx: ScenarioContext) -> list[SyntheticQuery]:
    """Degradacion progresiva de latencia hasta cruzar el umbral critico."""
    pool = _client_pool(ctx.rng, 40)
    truth = GroundTruth(scenario="zone_latency")
    queries: list[SyntheticQuery] = []
    for offset in _arrival_times(ctx):
        progress = (offset - ctx.start_offset_s) / ctx.duration_s
        # 1x al inicio, 21x al final: el p95 de la ventana supera los 500 ms
        # que la spec seccion 9 define como umbral critico de latencia.
        queries.append(
            _query(
                ctx,
                offset_s=offset,
                client_hash=ctx.rng.choice(pool),
                qname=domains.normal_domain(ctx.rng),
                qtype=_normal_qtype(ctx.rng),
                ground_truth=truth,
                latency_factor=1.0 + 20.0 * progress,
            )
        )
    return _sorted(queries)


def _build_nxdomain_spike(ctx: ScenarioContext) -> list[SyntheticQuery]:
    """Pico de NXDOMAIN por encima del 20 %, sin amenaza asociada."""
    pool = _client_pool(ctx.rng, 40)
    truth = GroundTruth(scenario="nxdomain_spike")
    return _sorted(
        [
            _query(
                ctx,
                offset_s=offset,
                client_hash=ctx.rng.choice(pool),
                qname=domains.normal_domain(ctx.rng),
                qtype=_normal_qtype(ctx.rng),
                ground_truth=truth,
                nxdomain_rate=0.28,
            )
            for offset in _arrival_times(ctx)
        ]
    )


def _build_resolver_saturation(ctx: ScenarioContext) -> list[SyntheticQuery]:
    """SERVFAIL, timeouts y cola de latencia dispersa (p99/p50 alto)."""
    pool = _client_pool(ctx.rng, 40)
    truth = GroundTruth(scenario="resolver_saturation")
    queries: list[SyntheticQuery] = []
    for offset in _arrival_times(ctx):
        # Una de cada seis consultas sanas se va a la cola larga.
        tail = ctx.rng.random() < 0.17
        queries.append(
            _query(
                ctx,
                offset_s=offset,
                client_hash=ctx.rng.choice(pool),
                qname=domains.normal_domain(ctx.rng),
                qtype=_normal_qtype(ctx.rng),
                ground_truth=truth,
                servfail_rate=0.12,
                timeout_rate=0.10,
                latency_factor=6.0 if tail else 1.2,
            )
        )
    return _sorted(queries)


# Orden fijo de la secuencia de demostracion.
_MIXED_SEQUENCE: tuple[str, ...] = (
    "normal",
    "dga_burst",
    "typosquatting",
    "tunneling",
    "beaconing",
    "zone_latency",
    "nxdomain_spike",
    "resolver_saturation",
)


def _build_mixed_demo(ctx: ScenarioContext) -> list[SyntheticQuery]:
    """Encadena todos los escenarios repartiendo la duracion total en partes iguales."""
    slice_s = ctx.duration_s / len(_MIXED_SEQUENCE)
    queries: list[SyntheticQuery] = []
    for index, name in enumerate(_MIXED_SEQUENCE):
        sub_ctx = replace(
            ctx,
            duration_s=slice_s,
            start_offset_s=ctx.start_offset_s + index * slice_s,
        )
        queries.extend(SCENARIOS[name].build(sub_ctx))
    return _sorted(queries)


SCENARIOS: dict[str, ScenarioSpec] = {
    "normal": ScenarioSpec(
        name="normal",
        description="Trafico sano: dominios comunes, latencia baja y NXDOMAIN residual.",
        build=_build_normal,
    ),
    "dga_burst": ScenarioSpec(
        name="dga_burst",
        description="Rafaga de dominios de alta entropia con NXDOMAIN dominante.",
        build=_build_dga_burst,
    ),
    "typosquatting": ScenarioSpec(
        name="typosquatting",
        description="Variantes enganosas de marcas ficticias a distancia de edicion corta.",
        build=_build_typosquatting,
    ),
    "tunneling": ScenarioSpec(
        name="tunneling",
        description="Consultas TXT con subdominios largos y unicos a alta frecuencia.",
        build=_build_tunneling,
    ),
    "beaconing": ScenarioSpec(
        name="beaconing",
        description="Consultas periodicas al mismo dominio con jitter bajo.",
        build=_build_beaconing,
    ),
    "zone_latency": ScenarioSpec(
        name="zone_latency",
        description="Degradacion progresiva de latencia hasta superar los 500 ms de p95.",
        build=_build_zone_latency,
    ),
    "nxdomain_spike": ScenarioSpec(
        name="nxdomain_spike",
        description="Tasa de NXDOMAIN por encima del 20 % sin amenaza asociada.",
        build=_build_nxdomain_spike,
    ),
    "resolver_saturation": ScenarioSpec(
        name="resolver_saturation",
        description="SERVFAIL, timeouts y dispersion p99/p50 alta por saturacion.",
        build=_build_resolver_saturation,
    ),
    "mixed_demo": ScenarioSpec(
        name="mixed_demo",
        description="Secuencia completa de todos los escenarios para el video de demo.",
        build=_build_mixed_demo,
        default_duration_s=480.0,
    ),
}


def list_scenarios() -> list[str]:
    """Nombres de escenario disponibles, en orden estable."""
    return list(SCENARIOS)


def get_scenario(name: str) -> ScenarioSpec:
    """Devuelve un escenario por nombre."""
    try:
        return SCENARIOS[name]
    except KeyError:
        disponibles = ", ".join(list_scenarios())
        raise KeyError(f"escenario desconocido: {name!r}. Disponibles: {disponibles}") from None
