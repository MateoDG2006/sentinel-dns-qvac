"""Agregador de calidad de experiencia (QoE) por sitio y zona.

Implementa la formula v1 de la spec seccion 9. El score se calcula sobre
ventanas fijas y se explica siempre con sus tres subscores y el numero de
muestras, para que un operador pueda auditar por que una zona esta en rojo.

Diseno:

- Los umbrales viven en ``config/qoe_thresholds.yaml``, nunca en el codigo.
- El nucleo opera sobre :class:`QoeSample`, un tipo propio del servicio con los
  campos minimos que necesita el calculo. La traduccion desde
  ``NormalizedDnsEvent`` se hace en el borde, cuando A1 este disponible.
- Convencion de rcode acordada con el frente A: un timeout llega como
  ``rcode="TIMEOUT"`` con ``timed_out=True`` y sin latencia. Los tres buckets
  de fallo son excluyentes, de modo que ningun evento se cuenta dos veces.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

__all__ = [
    "RCODE_NXDOMAIN",
    "RCODE_SERVFAIL",
    "RCODE_TIMEOUT",
    "MetricThresholds",
    "ZoneThresholds",
    "QoeThresholds",
    "QoeSample",
    "QoeWindowResult",
    "QoeAggregator",
    "load_thresholds",
    "normalize",
    "subscore",
]

RCODE_NXDOMAIN = "NXDOMAIN"
RCODE_SERVFAIL = "SERVFAIL"
RCODE_TIMEOUT = "TIMEOUT"

# Etiquetas de estado y causa. Coinciden con QoeStatus y QoePrimaryCause de
# app/domain/enums.py; se declaran aqui como str para que el servicio siga
# siendo utilizable antes de que A1 este en main.
STATUS_GOOD = "good"
STATUS_WARNING = "warning"
STATUS_CRITICAL = "critical"
STATUS_INSUFFICIENT_DATA = "insufficient_data"

CAUSE_LATENCY = "latencia_alta"
CAUSE_NXDOMAIN = "nxdomain_elevado"
CAUSE_SATURATION = "saturacion_probable"
CAUSE_INSUFFICIENT = "muestras_insuficientes"


# ---------------------------------------------------------------------------
# Umbrales
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MetricThresholds:
    """Par de puntos que define la rampa lineal de una metrica."""

    good: float
    critical: float


@dataclass(frozen=True, slots=True)
class ZoneThresholds:
    """Umbrales efectivos de una zona, ya resueltos contra los defaults."""

    latency_p95_ms: MetricThresholds
    nxdomain_rate: MetricThresholds
    servfail_rate: MetricThresholds
    timeout_rate: MetricThresholds
    latency_dispersion: MetricThresholds


@dataclass(frozen=True, slots=True)
class QoeThresholds:
    """Contenido de ``config/qoe_thresholds.yaml``."""

    version: str
    weight_latency: float
    weight_resolution: float
    weight_saturation: float
    good_min: float
    warning_min: float
    min_samples: int
    defaults: ZoneThresholds
    zones: dict[str, ZoneThresholds]

    def for_zone(self, zone_id: str) -> ZoneThresholds:
        return self.zones.get(zone_id, self.defaults)


def _metric(raw: dict[str, Any]) -> MetricThresholds:
    return MetricThresholds(good=float(raw["good"]), critical=float(raw["critical"]))


_METRIC_NAMES = (
    "latency_p95_ms",
    "nxdomain_rate",
    "servfail_rate",
    "timeout_rate",
    "latency_dispersion",
)


def _zone_thresholds(raw: dict[str, Any], base: ZoneThresholds | None = None) -> ZoneThresholds:
    """Construye umbrales de zona, heredando del default lo no declarado."""
    values: dict[str, MetricThresholds] = {}
    for name in _METRIC_NAMES:
        if name in raw:
            values[name] = _metric(raw[name])
        elif base is not None:
            values[name] = getattr(base, name)
        else:
            raise ValueError(f"falta el umbral obligatorio '{name}' en los defaults")
    return ZoneThresholds(**values)


def load_thresholds(path: str | Path) -> QoeThresholds:
    """Carga y valida el archivo de umbrales."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    weights = raw["weights"]
    total = weights["latency"] + weights["resolution"] + weights["saturation"]
    if not math.isclose(total, 1.0, abs_tol=1e-9):
        raise ValueError(f"los pesos de QoE deben sumar 1.0, suman {total}")

    defaults = _zone_thresholds(raw["defaults"])
    zones = {
        zone_id: _zone_thresholds(overrides or {}, base=defaults)
        for zone_id, overrides in (raw.get("zones") or {}).items()
    }
    status = raw["status"]
    if status["warning_min"] > status["good_min"]:
        raise ValueError("warning_min no puede ser mayor que good_min")

    return QoeThresholds(
        version=str(raw["version"]),
        weight_latency=float(weights["latency"]),
        weight_resolution=float(weights["resolution"]),
        weight_saturation=float(weights["saturation"]),
        good_min=float(status["good_min"]),
        warning_min=float(status["warning_min"]),
        min_samples=int(raw["min_samples"]),
        defaults=defaults,
        zones=zones,
    )


# ---------------------------------------------------------------------------
# Matematica del score
# ---------------------------------------------------------------------------


def normalize(value: float, thresholds: MetricThresholds) -> float:
    """Posicion de ``value`` en la rampa good -> critical, recortada a 0..1.

    Devuelve 0.0 cuando la metrica esta en su mejor estado y 1.0 cuando alcanza
    el punto critico. Soporta rampas descendentes (critical < good).
    """
    good, critical = thresholds.good, thresholds.critical
    if math.isclose(good, critical):
        return 0.0 if value == good else 1.0
    return min(1.0, max(0.0, (value - good) / (critical - good)))


def subscore(value: float, thresholds: MetricThresholds) -> float:
    """Subscore 0..100, donde 100 es el mejor estado posible."""
    return 100.0 * (1.0 - normalize(value, thresholds))


def _percentile(ordered: list[float], fraction: float) -> float:
    """Percentil con interpolacion lineal sobre una lista ya ordenada."""
    if not ordered:
        return 0.0
    if len(ordered) == 1:
        return ordered[0]
    position = fraction * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * weight


# ---------------------------------------------------------------------------
# Muestras y resultado
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class QoeSample:
    """Campos de un evento DNS que intervienen en el calculo de QoE."""

    event_ts: datetime
    site_id: str
    zone_id: str
    rcode: str
    latency_ms: float | None
    timed_out: bool


@dataclass(frozen=True, slots=True)
class QoeWindowResult:
    """Ventana calculada. Mapea 1:1 con la tabla `sentinel_dns.dns_qoe_1m`."""

    window_start: datetime
    site_id: str
    zone_id: str
    sample_count: int
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    nxdomain_rate: float
    servfail_rate: float
    timeout_rate: float
    saturation_index: float
    latency_score: float
    resolution_score: float
    saturation_score: float
    qoe_score: float
    status: str
    primary_cause: str
    calculation_version: str
    updated_at: datetime


# ---------------------------------------------------------------------------
# Agregador
# ---------------------------------------------------------------------------

WindowKey = tuple[str, str, datetime]


class QoeAggregator:
    """Acumula eventos en ventanas fijas y produce un score por ventana.

    El agregador no escribe en ningun lado: devuelve ventanas cerradas y el
    llamador decide que hacer con ellas.
    """

    def __init__(
        self,
        thresholds: QoeThresholds,
        *,
        window_seconds: int = 60,
        calculation_version: str | None = None,
        grace_seconds: float = 0.0,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds debe ser positivo")
        self._thresholds = thresholds
        self._window = timedelta(seconds=window_seconds)
        self._window_seconds = window_seconds
        self._calculation_version = calculation_version or thresholds.version
        self._grace = timedelta(seconds=grace_seconds)
        self._buckets: dict[WindowKey, list[QoeSample]] = defaultdict(list)

    # -- ingesta ------------------------------------------------------------

    def window_start_for(self, moment: datetime) -> datetime:
        """Inicio de la ventana fija que contiene ``moment``, en UTC."""
        moment = moment.astimezone(UTC)
        epoch_seconds = moment.timestamp()
        floored = math.floor(epoch_seconds / self._window_seconds) * self._window_seconds
        return datetime.fromtimestamp(floored, tz=UTC)

    def observe(self, sample: QoeSample) -> None:
        """Registra una muestra en su ventana correspondiente."""
        key = (sample.site_id, sample.zone_id, self.window_start_for(sample.event_ts))
        self._buckets[key].append(sample)

    @property
    def pending_windows(self) -> int:
        return len(self._buckets)

    # -- cierre de ventanas -------------------------------------------------

    def collect_due_windows(self, now: datetime) -> list[QoeWindowResult]:
        """Cierra y devuelve las ventanas cuyo periodo ya termino.

        Las ventanas cerradas se retiran del acumulador, de modo que llamar dos
        veces no produce duplicados.
        """
        now = now.astimezone(UTC)
        due = [key for key in self._buckets if key[2] + self._window + self._grace <= now]
        results = [self._build(key, self._buckets.pop(key), now) for key in sorted(due)]
        return results

    async def flush_due_windows(self, now: datetime) -> list[QoeWindowResult]:
        """Version asincrona del contrato de la spec seccion 8."""
        return self.collect_due_windows(now)

    def flush_all(self, now: datetime) -> list[QoeWindowResult]:
        """Cierra todas las ventanas abiertas. Pensado para tests y apagado."""
        keys = sorted(self._buckets)
        return [self._build(key, self._buckets.pop(key), now) for key in keys]

    # -- calculo ------------------------------------------------------------

    def _build(
        self, key: WindowKey, samples: list[QoeSample], now: datetime
    ) -> QoeWindowResult:
        site_id, zone_id, window_start = key
        limits = self._thresholds.for_zone(zone_id)
        total = len(samples)

        latencies = sorted(s.latency_ms for s in samples if s.latency_ms is not None)
        p50 = _percentile(latencies, 0.50)
        p95 = _percentile(latencies, 0.95)
        p99 = _percentile(latencies, 0.99)

        timeouts = sum(1 for s in samples if s.timed_out)
        # Los buckets son excluyentes: un timeout no cuenta ademas como SERVFAIL.
        servfails = sum(1 for s in samples if s.rcode == RCODE_SERVFAIL and not s.timed_out)
        nxdomains = sum(1 for s in samples if s.rcode == RCODE_NXDOMAIN)

        nxdomain_rate = nxdomains / total if total else 0.0
        servfail_rate = servfails / total if total else 0.0
        timeout_rate = timeouts / total if total else 0.0

        # Sin ninguna respuesta medida la cola es incalculable: se asume el peor
        # caso, porque significa que nada resolvio dentro de la ventana.
        dispersion = p99 / p50 if p50 > 0.0 else limits.latency_dispersion.critical

        saturation_index = max(
            normalize(servfail_rate, limits.servfail_rate),
            normalize(timeout_rate, limits.timeout_rate),
            normalize(dispersion, limits.latency_dispersion),
        )

        latency_score = subscore(p95, limits.latency_p95_ms) if latencies else 0.0
        resolution_score = subscore(nxdomain_rate, limits.nxdomain_rate)
        saturation_score = 100.0 * (1.0 - saturation_index)

        qoe_score = (
            self._thresholds.weight_latency * latency_score
            + self._thresholds.weight_resolution * resolution_score
            + self._thresholds.weight_saturation * saturation_score
        )

        if total < self._thresholds.min_samples:
            status = STATUS_INSUFFICIENT_DATA
            primary_cause = CAUSE_INSUFFICIENT
        else:
            status = self._status_for(qoe_score)
            primary_cause = self._cause_for(
                latency_score,
                resolution_score,
                saturation_score,
                has_latency=bool(latencies),
            )

        return QoeWindowResult(
            window_start=window_start,
            site_id=site_id,
            zone_id=zone_id,
            sample_count=total,
            latency_p50_ms=round(p50, 3),
            latency_p95_ms=round(p95, 3),
            latency_p99_ms=round(p99, 3),
            nxdomain_rate=round(nxdomain_rate, 6),
            servfail_rate=round(servfail_rate, 6),
            timeout_rate=round(timeout_rate, 6),
            saturation_index=round(saturation_index, 6),
            latency_score=round(latency_score, 3),
            resolution_score=round(resolution_score, 3),
            saturation_score=round(saturation_score, 3),
            qoe_score=round(qoe_score, 3),
            status=status,
            primary_cause=primary_cause,
            calculation_version=self._calculation_version,
            updated_at=now.astimezone(UTC),
        )

    def _status_for(self, qoe_score: float) -> str:
        if qoe_score >= self._thresholds.good_min:
            return STATUS_GOOD
        if qoe_score >= self._thresholds.warning_min:
            return STATUS_WARNING
        return STATUS_CRITICAL

    @staticmethod
    def _cause_for(
        latency: float, resolution: float, saturation: float, *, has_latency: bool
    ) -> str:
        """La causa principal es el subscore mas bajo (spec seccion 9).

        Si la ventana no tiene ninguna latencia medida, el subscore de latencia
        vale 0 por falta de datos y no por lentitud: en ese caso la latencia
        queda excluida como causa, porque el problema real es que nada
        resolvio. Los empates restantes se resuelven en el orden de peso de la
        formula: latencia, resolucion, saturacion.
        """
        candidates: list[tuple[float, str]] = [
            (resolution, CAUSE_NXDOMAIN),
            (saturation, CAUSE_SATURATION),
        ]
        if has_latency:
            candidates.insert(0, (latency, CAUSE_LATENCY))

        worst = min(score for score, _ in candidates)
        for score, cause in candidates:
            if math.isclose(score, worst):
                return cause
        return CAUSE_SATURATION
