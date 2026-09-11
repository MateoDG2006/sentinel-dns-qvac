"""Tests del productor sintetico (tarea C1).

Verifican dos cosas distintas:

1. **Invariantes del simulador**: determinismo por seed, coherencia entre
   ``rcode`` y ``timed_out``, orden temporal y limites de DNS.
2. **Compatibilidad con el detector**: que cada escenario de amenaza supere los
   umbrales declarados en ``config/features.yaml`` (frente A, tarea A3). Sin
   esto el simulador puede generar trafico que el detector nunca marca, y el
   fallo solo aparece en el E2E.

Los umbrales estan replicados como constantes porque ``config/features.yaml``
todavia no esta en `main`. Cuando A3 se mergee, leerlos del YAML.

Solo se usa la libreria estandar: estos tests no deben depender de rapidfuzz ni
de los contratos del dominio.
"""

import math
import random
from collections import Counter, defaultdict

from simulator import domains
from simulator.profiles import DEFAULT_ZONE, ZONE_PROFILES, get_profile
from simulator.scenarios import (
    RCODE_TIMEOUT,
    SCENARIOS,
    ScenarioContext,
    SyntheticQuery,
    list_scenarios,
)

# --- Umbrales espejo de config/features.yaml (frente A, tarea A3) -----------
DGA_ENTROPY_MIN = 3.6
DGA_SLD_LENGTH_MIN = 14
DGA_VOWEL_RATIO_MAX = 0.30
DGA_DIGIT_RATIO_MIN = 0.15
DGA_LONGEST_LABEL_MAX = 32
DGA_LABEL_COUNT_MAX = 4

TUNNELING_LONGEST_LABEL_MIN = 36
TYPOSQUATTING_MAX_DISTANCE = 2

BEACONING_QUERY_COUNT_MIN = 8
BEACONING_JITTER_RATIO_MAX = 0.12
BEACONING_INTERVAL_MIN_MS = 4_000
BEACONING_INTERVAL_MAX_MS = 180_000

# Umbrales criticos de QoE (spec seccion 9).
QOE_LATENCY_CRITICAL_MS = 500.0
QOE_NXDOMAIN_CRITICAL = 0.20

# Objetivo de recall por familia de amenaza (spec seccion 18).
RECALL_MIN = 0.80

# Limites de DNS.
QNAME_MAX_LENGTH = 253
LABEL_MAX_LENGTH = 63

SEED = 42
DURATION_S = 60.0
MIXED_DURATION_S = 480.0


# --- Utilidades -------------------------------------------------------------


def build(
    scenario: str, *, seed: int = SEED, duration_s: float | None = None
) -> list[SyntheticQuery]:
    """Construye un escenario con parametros reproducibles."""
    if duration_s is None:
        duration_s = MIXED_DURATION_S if scenario == "mixed_demo" else DURATION_S
    ctx = ScenarioContext(
        rng=random.Random(seed),
        profile=get_profile("zona-centro"),
        site_id="pop-bog",
        rate_per_s=20.0,
        duration_s=duration_s,
    )
    return SCENARIOS[scenario].build(ctx)


def threats(scenario: str, threat_type: str) -> list[SyntheticQuery]:
    return [q for q in build(scenario) if q.ground_truth.threat_type == threat_type]


def shannon_entropy(text: str) -> float:
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def levenshtein(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            current.append(
                min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (char_a != char_b))
            )
        previous = current
    return previous[-1]


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(int(len(ordered) * fraction), len(ordered) - 1)
    return ordered[index]


def latencies(queries: list[SyntheticQuery]) -> list[float]:
    return [q.latency_ms for q in queries if q.latency_ms is not None]


def rate_of(queries: list[SyntheticQuery], predicate) -> float:
    return sum(1 for q in queries if predicate(q)) / len(queries)


# --- Catalogo ---------------------------------------------------------------


def test_estan_declarados_los_nueve_escenarios_de_la_spec() -> None:
    esperados = {
        "normal",
        "dga_burst",
        "typosquatting",
        "tunneling",
        "beaconing",
        "zone_latency",
        "nxdomain_spike",
        "resolver_saturation",
        "mixed_demo",
    }
    assert set(list_scenarios()) == esperados


def test_todo_escenario_produce_eventos() -> None:
    for nombre in list_scenarios():
        assert build(nombre), f"{nombre} no genero eventos"


# --- Invariantes ------------------------------------------------------------


def test_misma_seed_produce_la_misma_secuencia() -> None:
    for nombre in list_scenarios():
        assert build(nombre, seed=7) == build(nombre, seed=7), f"{nombre} no es determinista"


def test_seeds_distintas_producen_secuencias_distintas() -> None:
    assert build("normal", seed=1) != build("normal", seed=2)


def test_rcode_timeout_equivale_a_timed_out() -> None:
    """Evita el doble conteo de SERVFAIL y timeout en el agregador QoE."""
    for nombre in list_scenarios():
        for q in build(nombre):
            assert (q.rcode == RCODE_TIMEOUT) == q.timed_out, f"{nombre}: {q.rcode}/{q.timed_out}"


def test_los_timeouts_no_reportan_latencia_ni_bytes() -> None:
    for nombre in list_scenarios():
        for q in build(nombre):
            if q.timed_out:
                assert q.latency_ms is None
                assert q.response_bytes is None
            else:
                assert q.latency_ms is not None


def test_la_salida_esta_ordenada_por_tiempo() -> None:
    for nombre in list_scenarios():
        eventos = build(nombre)
        assert eventos == sorted(eventos, key=lambda q: q.offset_s), f"{nombre} desordenado"


def test_los_eventos_caen_dentro_de_la_ventana() -> None:
    for nombre in list_scenarios():
        duracion = MIXED_DURATION_S if nombre == "mixed_demo" else DURATION_S
        for q in build(nombre):
            assert 0.0 <= q.offset_s <= duracion, f"{nombre}: offset {q.offset_s} fuera de rango"


def test_los_qname_respetan_los_limites_de_dns() -> None:
    for nombre in list_scenarios():
        for q in build(nombre):
            assert len(q.qname) <= QNAME_MAX_LENGTH, f"{nombre}: qname de {len(q.qname)}"
            for etiqueta in q.qname.split("."):
                assert 0 < len(etiqueta) <= LABEL_MAX_LENGTH


def test_los_dominios_usan_solo_tlds_reservados() -> None:
    """Ningun dominio sintetico debe poder resolver en la Internet real."""
    for nombre in list_scenarios():
        for q in build(nombre):
            assert q.qname.rsplit(".", 1)[-1] in domains.SYNTHETIC_TLDS


# --- Compatibilidad con el detector -----------------------------------------


def test_dga_supera_los_umbrales_del_detector() -> None:
    consultas = threats("dga_burst", "dga")
    aprobadas = 0
    for q in consultas:
        etiquetas = q.qname.split(".")
        sld = etiquetas[0]
        vocales = sum(c in "aeiou" for c in sld) / len(sld)
        digitos = sum(c.isdigit() for c in sld) / len(sld)
        if (
            shannon_entropy(sld) >= DGA_ENTROPY_MIN
            and len(sld) >= DGA_SLD_LENGTH_MIN
            and vocales <= DGA_VOWEL_RATIO_MAX
            and digitos >= DGA_DIGIT_RATIO_MIN
            and max(len(e) for e in etiquetas) <= DGA_LONGEST_LABEL_MAX
            and len(etiquetas) <= DGA_LABEL_COUNT_MAX
        ):
            aprobadas += 1
    assert aprobadas / len(consultas) >= RECALL_MIN


def test_tunneling_usa_txt_y_etiquetas_suficientemente_largas() -> None:
    for q in threats("tunneling", "dns_tunneling"):
        assert q.qtype == "TXT"
        assert max(len(e) for e in q.qname.split(".")) >= TUNNELING_LONGEST_LABEL_MIN


def test_tunneling_genera_subdominios_unicos() -> None:
    consultas = threats("tunneling", "dns_tunneling")
    assert len({q.qname for q in consultas}) == len(consultas)


def test_typosquatting_apunta_a_las_marcas_declaradas() -> None:
    for q in threats("typosquatting", "typosquatting"):
        assert q.ground_truth.target_brand in domains.FICTIONAL_BRANDS


def test_typosquatting_queda_a_distancia_corta_o_usa_un_afijo() -> None:
    for q in threats("typosquatting", "typosquatting"):
        sld = q.qname.split(".")[0]
        marca = q.ground_truth.target_brand
        assert marca is not None
        cerca = levenshtein(sld, marca) <= TYPOSQUATTING_MAX_DISTANCE
        con_afijo = marca in sld
        assert cerca or con_afijo, f"{sld} no es reconocible como variante de {marca}"


def test_beaconing_cumple_volumen_jitter_e_intervalo() -> None:
    campanas: dict[tuple[str, str], list[float]] = defaultdict(list)
    for q in threats("beaconing", "beaconing"):
        campanas[(q.client_hash, q.qname)].append(q.offset_s)

    assert campanas, "el escenario no genero ninguna campana"
    for (_, dominio), momentos in campanas.items():
        momentos.sort()
        assert len(momentos) >= BEACONING_QUERY_COUNT_MIN, f"{dominio}: {len(momentos)} consultas"
        intervalos = [b - a for a, b in zip(momentos, momentos[1:], strict=False)]
        medio_ms = (sum(intervalos) / len(intervalos)) * 1000
        jitter = ((max(intervalos) - min(intervalos)) / 2 * 1000) / medio_ms
        assert jitter <= BEACONING_JITTER_RATIO_MAX, f"{dominio}: jitter {jitter:.3f}"
        assert BEACONING_INTERVAL_MIN_MS <= medio_ms <= BEACONING_INTERVAL_MAX_MS


def test_el_trafico_normal_no_usa_qtypes_sospechosos() -> None:
    """Evita falsos positivos: el fondo sano nunca debe consultar TXT."""
    for q in build("normal"):
        assert q.qtype in {"A", "AAAA", "HTTPS"}


def test_mixed_demo_contiene_las_cuatro_familias_de_amenaza() -> None:
    familias = {q.ground_truth.threat_type for q in build("mixed_demo")}
    assert {"dga", "typosquatting", "dns_tunneling", "beaconing"} <= familias


# --- Escenarios de QoE ------------------------------------------------------


def test_zone_latency_cruza_el_umbral_critico_de_latencia() -> None:
    p95 = percentile(latencies(build("zone_latency")), 0.95)
    assert p95 > QOE_LATENCY_CRITICAL_MS, f"p95 de {p95:.1f} ms no llega al umbral critico"


def test_nxdomain_spike_supera_la_tasa_critica() -> None:
    tasa = rate_of(build("nxdomain_spike"), lambda q: q.rcode == "NXDOMAIN")
    assert tasa > QOE_NXDOMAIN_CRITICAL, f"NXDOMAIN al {tasa:.1%}"


def test_resolver_saturation_genera_fallos_y_cola_dispersa() -> None:
    eventos = build("resolver_saturation")
    assert rate_of(eventos, lambda q: q.rcode == "SERVFAIL") > 0.10
    assert rate_of(eventos, lambda q: q.timed_out) > 0.05
    medidas = latencies(eventos)
    dispersion = percentile(medidas, 0.99) / percentile(medidas, 0.50)
    assert dispersion > 2.0, f"p99/p50 = {dispersion:.1f}"


def test_el_trafico_normal_se_mantiene_sano() -> None:
    eventos = build("normal")
    assert percentile(latencies(eventos), 0.95) < 100.0
    assert rate_of(eventos, lambda q: q.rcode == "NXDOMAIN") < 0.05


# --- Perfiles ---------------------------------------------------------------


def test_una_zona_desconocida_hereda_los_valores_por_defecto() -> None:
    perfil = get_profile("zona-inexistente")
    base = ZONE_PROFILES[DEFAULT_ZONE]
    assert perfil.zone_id == "zona-inexistente"
    assert perfil.latency_mode_ms == base.latency_mode_ms
    assert perfil.nxdomain_rate == base.nxdomain_rate


def test_la_latencia_muestreada_cae_dentro_del_rango_del_perfil() -> None:
    rng = random.Random(SEED)
    for perfil in ZONE_PROFILES.values():
        for _ in range(200):
            valor = perfil.sample_latency_ms(rng)
            assert perfil.latency_low_ms <= valor <= perfil.latency_high_ms
