# Operación local

## Entornos

- **Host + Compose parcial (camino actual):** Kafka, ClickHouse y Grafana en Docker; API/consumer/QVAC con `make api` en el host.
- Docker Compose `full` (C4): demo canónica cuando existan Wazuh, Prometheus y sentinel-api en el stack.
- Kubernetes: manifiestos renderizados y validados; no se exige despliegue.

## Arranque en el host

1. `make env` y rellenar `SENTINEL_WEBHOOK_TOKEN` (nunca commitear `.env`).
2. `make sync` (`uv sync` + `npm install` para `@qvac/sdk` local).
3. `make bootstrap` una vez (GGUF en `data/qvac/`); después `make qvac-smoke`.
4. `make up` (Kafka + ClickHouse/Grafana).
5. `make api` — fuerza `SENTINEL_KAFKA__BOOTSTRAP_SERVERS=localhost:29092` y `SENTINEL_CLICKHOUSE__HOST=localhost`.
6. Lab: `http://127.0.0.1:8000/lab`. Simulador: `uv run python -m simulator.main --scenario mixed_demo --seed 42`.

El proceso comparte un solo `PredictionService` para Kafka, webhook y lab:

```text
evento → heurísticas + QVAC local → outbox SQLite → dispatcher Wazuh
                                 ↘ agregador QoE → ClickHouse
```

## Flags de workers

Por defecto están encendidos (salvo unit tests, que los apagan):

| Variable | Efecto si `0`/`false` |
|---|---|
| `SENTINEL_ENABLE_KAFKA_CONSUMER` | No consume `dns.telemetry.normalized`; ready marca Kafka degradado. |
| `SENTINEL_ENABLE_WAZUH_DISPATCHER` | No drena el outbox. También queda idle si no hay usuario/contraseña Wazuh (log `wazuh_dispatcher_skipped`). |
| `SENTINEL_ENABLE_QOE_FLUSH` | El agregador observa eventos pero no escribe ClickHouse. |

Outbox durable: `SENTINEL_OUTBOX__PATH` (SQLite). `/health/ready` reporta `outbox` `up` / `durable_sqlite` cuando el lifespan lo abrió.

## Salud

- `/health/live`: proceso/event loop.
- `/health/ready`: Kafka, outbox y configuración. QVAC down se reporta **degradado** (fallback heurístico) y no hace 503. Kafka down con consumer habilitado sí hace 503.
- `/metrics`: métricas agregadas sin `qname`, `client_hash`, `site_id` ni `zone_id` como labels.

## Degradación

| Falla | Respuesta |
|---|---|
| QVAC timeout/caído | Fallback heurístico, retry y alerta técnica agregada. |
| Wazuh caído | Outbox durable y entrega al recuperarse. |
| Wazuh `401` | Renovar JWT una vez. |
| Wazuh `429` | Respetar `Retry-After` y aplicar jitter. |
| ClickHouse caído | No inventar score; métrica `qoe_flush` `unavailable`/`error`. |
| Outbox lleno | Pausar Kafka y devolver `429` al webhook. |
| Evento inválido | DLQ local con razón; continuar partición. |

## Recuperación

Al reiniciar, Sentinel reanuda offsets y outbox sin duplicados observables. Amenaza y alerta operativa pueden coexistir (`event_id` + `record_type`). La recuperación de QVAC debe retirar el estado degradado y conservar la alerta previa como evidencia.

## Kubernetes

Validar render Kustomize, esquemas con kubeconform, dry-run del cliente y ausencia de LoadBalancer, `latest`, privilegios o secretos literales.
