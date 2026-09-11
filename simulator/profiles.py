"""Perfiles de red por zona para el trafico sintetico.

Un ``ZoneProfile`` describe el comportamiento *base* (sano) de una zona: como se
distribuye la latencia y con que probabilidad aparece cada tipo de fallo. Los
escenarios de ``simulator.scenarios`` parten de este perfil y le aplican
modificadores (por ejemplo, subir NXDOMAIN o degradar la latencia).

Todo es determinista: los samplers reciben un ``random.Random`` ya sembrado.
"""

import random
from dataclasses import dataclass

__all__ = [
    "ZoneProfile",
    "ZONE_PROFILES",
    "DEFAULT_ZONE",
    "SITES",
    "get_profile",
]


@dataclass(frozen=True, slots=True)
class ZoneProfile:
    """Comportamiento base de una zona en condiciones normales."""

    zone_id: str
    # Latencia modelada como distribucion triangular (ms).
    latency_low_ms: float
    latency_mode_ms: float
    latency_high_ms: float
    # Probabilidad base de cada resultado anomalo (0..1).
    nxdomain_rate: float
    servfail_rate: float
    timeout_rate: float
    # Rango de tamano de respuesta (bytes).
    response_bytes_low: int = 64
    response_bytes_high: int = 280

    def sample_latency_ms(self, rng: random.Random) -> float:
        """Latencia de una consulta sana, redondeada a centesimas de ms."""
        value = rng.triangular(self.latency_low_ms, self.latency_high_ms, self.latency_mode_ms)
        return round(value, 2)

    def sample_response_bytes(self, rng: random.Random) -> int:
        return rng.randint(self.response_bytes_low, self.response_bytes_high)


# Zonas conocidas. Los numeros son plausibles para una demo, no medidas reales.
ZONE_PROFILES: dict[str, ZoneProfile] = {
    "zona-centro": ZoneProfile(
        zone_id="zona-centro",
        latency_low_ms=12.0,
        latency_mode_ms=28.0,
        latency_high_ms=70.0,
        nxdomain_rate=0.020,
        servfail_rate=0.003,
        timeout_rate=0.002,
    ),
    "zona-norte": ZoneProfile(
        zone_id="zona-norte",
        latency_low_ms=20.0,
        latency_mode_ms=45.0,
        latency_high_ms=110.0,
        nxdomain_rate=0.030,
        servfail_rate=0.005,
        timeout_rate=0.004,
    ),
    "zona-sur": ZoneProfile(
        zone_id="zona-sur",
        latency_low_ms=25.0,
        latency_mode_ms=55.0,
        latency_high_ms=140.0,
        nxdomain_rate=0.040,
        servfail_rate=0.006,
        timeout_rate=0.005,
    ),
    "zona-oeste": ZoneProfile(
        zone_id="zona-oeste",
        latency_low_ms=16.0,
        latency_mode_ms=36.0,
        latency_high_ms=90.0,
        nxdomain_rate=0.025,
        servfail_rate=0.004,
        timeout_rate=0.003,
    ),
}

DEFAULT_ZONE = "zona-centro"

# Identificadores de sitio / POP sinteticos.
SITES: tuple[str, ...] = ("pop-bog", "pop-mde", "pop-cli", "pop-baq")


def get_profile(zone_id: str | None) -> ZoneProfile:
    """Devuelve el perfil de una zona.

    Si la zona no esta registrada se sintetiza una copia del perfil por defecto
    con ese ``zone_id``, para que el simulador acepte zonas arbitrarias por CLI.
    """
    if zone_id is None:
        return ZONE_PROFILES[DEFAULT_ZONE]
    known = ZONE_PROFILES.get(zone_id)
    if known is not None:
        return known
    base = ZONE_PROFILES[DEFAULT_ZONE]
    return ZoneProfile(
        zone_id=zone_id,
        latency_low_ms=base.latency_low_ms,
        latency_mode_ms=base.latency_mode_ms,
        latency_high_ms=base.latency_high_ms,
        nxdomain_rate=base.nxdomain_rate,
        servfail_rate=base.servfail_rate,
        timeout_rate=base.timeout_rate,
    )
