-- Esquema de ventanas QoE de Sentinel-DNS.
--
-- Fuente: PLAN_IMPLEMENTACION_SENTINEL_DNS.md seccion 9, tabla
-- `sentinel_dns.dns_qoe_1m`. Los nombres de base y tabla estan congelados en
-- app/constants/clickhouse.py: cambiarlos requiere un ADR.
--
-- Este archivo lo ejecuta el contenedor de ClickHouse al inicializarse, via
-- /docker-entrypoint-initdb.d/. Debe ser idempotente: se corre en cada arranque
-- con volumen nuevo y no debe fallar si los objetos ya existen.

CREATE DATABASE IF NOT EXISTS sentinel_dns;

-- Una fila por (sitio, zona, ventana de 60 s).
--
-- Motor ReplacingMergeTree ordenado por la clave logica de la ventana: si el
-- agente reintenta la escritura de una ventana ya insertada, la version con
-- `updated_at` mas reciente reemplaza a la anterior. Esto da idempotencia sin
-- necesidad de borrar ni de consultar antes de insertar.
CREATE TABLE IF NOT EXISTS sentinel_dns.dns_qoe_1m
(
    -- Identidad de la ventana.
    `window_start`        DateTime64(3, 'UTC')    COMMENT 'Inicio de la ventana de 60 s',
    `site_id`             LowCardinality(String)  COMMENT 'POP o sitio',
    `zone_id`             LowCardinality(String)  COMMENT 'Zona cliente',

    -- Evidencia: sin esto el score no es auditable.
    `sample_count`        UInt64                  COMMENT 'Consultas observadas en la ventana',

    -- Latencia.
    `latency_p50_ms`      Float32                 COMMENT 'Tendencia central',
    `latency_p95_ms`      Float32                 COMMENT 'Experiencia degradada',
    `latency_p99_ms`      Float32                 COMMENT 'Cola extrema',

    -- Tasas de fallo. Excluyentes entre si: un timeout no cuenta ademas como
    -- SERVFAIL. Expresadas como fraccion 0..1, no como porcentaje.
    `nxdomain_rate`       Float32                 COMMENT 'Fraccion de NXDOMAIN',
    `servfail_rate`       Float32                 COMMENT 'Fraccion de SERVFAIL',
    `timeout_rate`        Float32                 COMMENT 'Fraccion de timeouts',
    `saturation_index`    Float32                 COMMENT 'Peor senal de saturacion, 0..1',

    -- Subscores 0..100. Se guardan los tres para que el score final sea
    -- explicable en el dashboard sin recalcular nada.
    `latency_score`       Float32                 COMMENT 'Subscore de latencia',
    `resolution_score`    Float32                 COMMENT 'Subscore de resolucion',
    `saturation_score`    Float32                 COMMENT 'Subscore de saturacion',
    `qoe_score`           Float32                 COMMENT '0.45*lat + 0.30*res + 0.25*sat',

    -- Interpretacion operativa.
    `status`              Enum8(
                              'good' = 1,
                              'warning' = 2,
                              'critical' = 3,
                              'insufficient_data' = 4
                          )                       COMMENT 'Estado de la ventana',
    `primary_cause`       LowCardinality(String)  COMMENT 'Subscore mas bajo, como etiqueta',

    -- Auditoria.
    `calculation_version` LowCardinality(String)  COMMENT 'Version de la formula aplicada',
    `updated_at`          DateTime64(3, 'UTC')    COMMENT 'Version de la fila; gana la mas reciente'
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMMDD(window_start)
ORDER BY (site_id, zone_id, window_start)
TTL toDateTime(window_start) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- Vista de consulta para Grafana.
--
-- `FINAL` fuerza la deduplicacion del ReplacingMergeTree en tiempo de lectura:
-- sin esto, una ventana reescrita puede aparecer dos veces hasta que ClickHouse
-- haga el merge en segundo plano. El volumen de la demo (una fila por minuto,
-- sitio y zona) hace que el costo sea irrelevante.
--
-- Ademas expone las tasas ya convertidas a porcentaje, para que los paneles no
-- tengan que multiplicar por 100 en cada query.
CREATE OR REPLACE VIEW sentinel_dns.dns_qoe_1m_latest AS
SELECT
    window_start,
    site_id,
    zone_id,
    sample_count,
    latency_p50_ms,
    latency_p95_ms,
    latency_p99_ms,
    nxdomain_rate,
    servfail_rate,
    timeout_rate,
    saturation_index,
    latency_score,
    resolution_score,
    saturation_score,
    qoe_score,
    status,
    primary_cause,
    calculation_version,
    updated_at,
    nxdomain_rate * 100 AS nxdomain_pct,
    servfail_rate * 100 AS servfail_pct,
    timeout_rate  * 100 AS timeout_pct,
    -- Dispersion de la cola: la senal que distingue saturacion de lentitud
    -- generalizada. Se protege la division cuando no hubo latencias medidas.
    if(latency_p50_ms > 0, latency_p99_ms / latency_p50_ms, 0) AS latency_dispersion
FROM sentinel_dns.dns_qoe_1m
FINAL;
