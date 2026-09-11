"""Generadores deterministas de nombres DNS sinteticos para los escenarios.

Reglas de este modulo:

- Nada de marcas ni dominios reales. Todo el material es ficticio y usa TLDs
  reservados que nunca resuelven de verdad (RFC 2606 / RFC 6761).
- Cada funcion recibe un ``random.Random`` ya sembrado: misma seed -> misma
  salida. No se usa el modulo ``random`` global.
- Aca solo se construyen strings. El timing, las tasas y el ground truth viven
  en ``simulator.scenarios`` y ``simulator.profiles``.
"""

import random
from typing import NamedTuple

__all__ = [
    "SYNTHETIC_TLDS",
    "COMMON_LABELS",
    "FICTIONAL_BRANDS",
    "TypoDomain",
    "synthetic_tld",
    "normal_domain",
    "dga_domain",
    "typosquat_domain",
    "tunneling_qname",
    "beaconing_domain",
]

# TLDs reservados para pruebas: no resuelven en la Internet real.
SYNTHETIC_TLDS: tuple[str, ...] = ("test", "example", "invalid", "lab", "demo")

# Etiquetas neutras y pronunciables para dominios de aspecto normal.
COMMON_LABELS: tuple[str, ...] = (
    "portal", "cuenta", "tienda", "correo", "pagos", "soporte", "noticias",
    "video", "musica", "clima", "mapa", "buscar", "nube", "agenda", "chat",
    "panel", "acceso", "ayuda", "blog", "foro", "descargas", "estado",
)

# Marcas ficticias autorizadas para generar typosquatting.
# No corresponden a ninguna entidad real.
#
# IMPORTANTE: esta lista debe ser identica a `config/brands.yaml`, que consume
# el detector del frente A (tarea A3). Si divergen, el simulador genera
# variantes que el detector no reconoce. Copiada de esa fuente de verdad;
# reemplazar por lectura del YAML cuando A3 este en main.
FICTIONAL_BRANDS: tuple[str, ...] = (
    "acmebank", "northwind", "globexmail", "initechvpn",
    "soylentcorp", "hoolicloud", "initrode", "rivercity",
)

# Sustituciones letra -> digito. Es la inversa del mapa `homoglyphs.substitutions`
# de `config/features.yaml`, que normaliza en sentido digito -> letra.
_HOMOGLYPHS: dict[str, str] = {
    "o": "0", "l": "1", "e": "3", "a": "4", "s": "5", "t": "7", "b": "8",
}

# Secuencias visualmente confundibles, inversa de `homoglyphs.sequences`.
_HOMOGLYPH_SEQUENCES: dict[str, str] = {"m": "rn", "w": "vv", "d": "cl"}

# Afijos enganosos declarados en `config/features.yaml` (typosquatting).
_DECEPTIVE_PREFIXES: tuple[str, ...] = (
    "login", "secure", "verify", "account", "support",
    "auth", "update", "confirm", "billing", "webmail", "signin",
)
_DECEPTIVE_SUFFIXES: tuple[str, ...] = (
    "login", "secure", "verify", "account", "support",
    "online", "portal", "sso", "auth", "update", "confirm",
)
_CONSONANTS = "bcdfghjklmnpqrstvwxyz"
_VOWELS = "aeiou"
_BASE32 = "abcdefghijklmnopqrstuvwxyz234567"


class TypoDomain(NamedTuple):
    """Dominio de typosquatting mas los datos que necesita el ground truth."""

    domain: str
    target_brand: str
    technique: str


def synthetic_tld(rng: random.Random) -> str:
    """Elige un TLD sintetico."""
    return rng.choice(SYNTHETIC_TLDS)


def normal_domain(rng: random.Random) -> str:
    """Dominio corto, pronunciable y de baja entropia."""
    labels = [rng.choice(COMMON_LABELS)]
    if rng.random() < 0.35:
        labels.append(rng.choice(COMMON_LABELS))
    separator = "-" if len(labels) > 1 and rng.random() < 0.5 else ""
    second_level = separator.join(labels)
    return f"{second_level}.{synthetic_tld(rng)}"


def dga_domain(rng: random.Random, *, min_len: int = 18, max_len: int = 30) -> str:
    """Etiqueta de alta entropia: mezcla de consonantes y digitos, sin silabas.

    El sesgo hacia consonantes y digitos baja el ratio de vocales y sube el de
    digitos, las senales que usa la heuristica de DGA. El largo minimo queda
    por encima de `dga.sld_length_min` (14) de `config/features.yaml`, y el
    maximo por debajo de `dga.longest_label_max` (32).
    """
    length = rng.randint(min_len, max_len)
    alphabet = _CONSONANTS + _VOWELS + "0123456789"
    weights = [3] * len(_CONSONANTS) + [1] * len(_VOWELS) + [4] * 10
    label = "".join(rng.choices(alphabet, weights=weights, k=length))
    return f"{label}.{synthetic_tld(rng)}"


def typosquat_domain(rng: random.Random, brand: str | None = None) -> TypoDomain:
    """Variante enganosa de una marca ficticia, a distancia de edicion 1-2.

    Si no se pasa ``brand`` se elige una de :data:`FICTIONAL_BRANDS`. El
    resultado siempre difiere de la marca original.
    """
    target = brand if brand is not None else rng.choice(FICTIONAL_BRANDS)
    techniques = (
        "insert", "delete", "transpose", "substitute",
        "homoglyph", "sequence", "prefix", "suffix",
    )

    for technique in rng.sample(techniques, k=len(techniques)):
        typo = _apply_typo(rng, target, technique)
        if typo != target:
            return TypoDomain(f"{typo}.{synthetic_tld(rng)}", target, technique)

    # Fallback defensivo: duplicar una letra siempre cambia el string.
    doubled = target[0] + target
    return TypoDomain(f"{doubled}.{synthetic_tld(rng)}", target, "duplicate")


def _apply_typo(rng: random.Random, target: str, technique: str) -> str:
    chars = list(target)
    if technique == "insert":
        chars.insert(rng.randint(0, len(chars)), rng.choice(_CONSONANTS))
    elif technique == "delete" and len(chars) > 4:
        del chars[rng.randrange(len(chars))]
    elif technique == "transpose" and len(chars) > 2:
        i = rng.randrange(len(chars) - 1)
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
    elif technique == "substitute":
        i = rng.randrange(len(chars))
        chars[i] = rng.choice(_CONSONANTS)
    elif technique == "homoglyph":
        positions = [i for i, c in enumerate(chars) if c in _HOMOGLYPHS]
        if positions:
            i = rng.choice(positions)
            chars[i] = _HOMOGLYPHS[chars[i]]
    elif technique == "sequence":
        positions = [i for i, c in enumerate(chars) if c in _HOMOGLYPH_SEQUENCES]
        if positions:
            i = rng.choice(positions)
            chars[i] = _HOMOGLYPH_SEQUENCES[chars[i]]
    elif technique == "prefix":
        return f"{rng.choice(_DECEPTIVE_PREFIXES)}-{target}"
    elif technique == "suffix":
        return f"{target}-{rng.choice(_DECEPTIVE_SUFFIXES)}"
    return "".join(chars)


def tunneling_qname(rng: random.Random, base_domain: str | None = None) -> str:
    """Subdominio largo y unico bajo un dominio de exfiltracion controlado.

    Simula datos codificados en base32 dentro del nombre de consulta: alta
    entropia, etiqueta muy larga y unicidad por consulta.
    """
    base = base_domain if base_domain is not None else f"tunnel.{synthetic_tld(rng)}"
    payload_len = rng.randint(60, 100)
    payload = "".join(rng.choices(_BASE32, k=payload_len))
    # Etiquetas de 44 caracteres: por encima de `tunneling.longest_label_min`
    # (36) de config/features.yaml y por debajo del limite DNS de 63.
    chunk = 44
    chunks = [payload[i : i + chunk] for i in range(0, len(payload), chunk)]
    return ".".join([*chunks, base])


def beaconing_domain(rng: random.Random) -> str:
    """Dominio estable tipo C2, pensado para ser reusado en consultas periodicas."""
    word = rng.choice(("sync", "update", "poll", "check", "heartbeat", "ping"))
    suffix = "".join(rng.choices(_CONSONANTS, k=4))
    return f"{word}-{suffix}.{synthetic_tld(rng)}"
