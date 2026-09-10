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
# No corresponden a ninguna entidad real. Fuente de verdad provisional hasta
# que exista ``config/brands.yaml`` (coordinar con el frente A / tarea A3).
FICTIONAL_BRANDS: tuple[str, ...] = (
    "examplebank", "acmeshop", "globexmail", "initechcloud", "umbrellahealth",
    "hooliapp", "piedpiper", "soylentfoods", "wonkaindustries", "wayneenterprises",
)

_HOMOGLYPHS: dict[str, str] = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}
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


def dga_domain(rng: random.Random, *, min_len: int = 12, max_len: int = 24) -> str:
    """Etiqueta de alta entropia: mezcla de consonantes y digitos, sin silabas.

    El sesgo hacia consonantes y digitos baja el ratio de vocales, una de las
    senales que usan las heuristicas de DGA.
    """
    length = rng.randint(min_len, max_len)
    alphabet = _CONSONANTS + _VOWELS + "0123456789"
    weights = [3] * len(_CONSONANTS) + [1] * len(_VOWELS) + [3] * 10
    label = "".join(rng.choices(alphabet, weights=weights, k=length))
    return f"{label}.{synthetic_tld(rng)}"


def typosquat_domain(rng: random.Random, brand: str | None = None) -> TypoDomain:
    """Variante enganosa de una marca ficticia, a distancia de edicion 1-2.

    Si no se pasa ``brand`` se elige una de :data:`FICTIONAL_BRANDS`. El
    resultado siempre difiere de la marca original.
    """
    target = brand if brand is not None else rng.choice(FICTIONAL_BRANDS)
    techniques = ("insert", "delete", "transpose", "substitute", "homoglyph", "prefix", "suffix")

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
    elif technique == "prefix":
        return f"{rng.choice(('login', 'secure', 'account', 'my'))}-{target}"
    elif technique == "suffix":
        return f"{target}-{rng.choice(('support', 'verify', 'secure', 'help'))}"
    return "".join(chars)


def tunneling_qname(rng: random.Random, base_domain: str | None = None) -> str:
    """Subdominio largo y unico bajo un dominio de exfiltracion controlado.

    Simula datos codificados en base32 dentro del nombre de consulta: alta
    entropia, etiqueta muy larga y unicidad por consulta.
    """
    base = base_domain if base_domain is not None else f"tunnel.{synthetic_tld(rng)}"
    payload_len = rng.randint(40, 60)
    payload = "".join(rng.choices(_BASE32, k=payload_len))
    # Partir en etiquetas de <=63 caracteres para respetar el limite de DNS.
    chunks = [payload[i : i + 32] for i in range(0, len(payload), 32)]
    return ".".join([*chunks, base])


def beaconing_domain(rng: random.Random) -> str:
    """Dominio estable tipo C2, pensado para ser reusado en consultas periodicas."""
    word = rng.choice(("sync", "update", "poll", "check", "heartbeat", "ping"))
    suffix = "".join(rng.choices(_CONSONANTS, k=4))
    return f"{word}-{suffix}.{synthetic_tld(rng)}"
