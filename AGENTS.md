# Sentinel-DNS: reglas para agentes

## Misión

Construir un consumidor adicional del stream DNS que detecte amenazas con reglas y QVAC local, envíe alertas a Wazuh y calcule QoE por sitio/zona en ClickHouse para Grafana.

## Reglas no negociables

1. Toda inferencia corre localmente con el SDK Python de QVAC. Ninguna consulta DNS ni dato derivado puede salir de la infraestructura.
2. No agregar APIs SaaS, reputación remota, telemetría cloud, trackers, descargas de modelos en runtime ni exportadores externos.
3. Kafka es la fuente principal. `POST /api/v1/predictions` reutiliza el mismo `PredictionService`; no sustituye el flujo del stream.
4. Si QVAC falla, continuar con heurísticas locales, persistir el reintento y producir una alerta técnica para Wazuh.
5. Sentinel-DNS es un consumidor adicional: no cambiar BIND9, Vector ni el pipeline de producción.
6. En el perfil del hackathon solo se aceptan eventos con `synthetic=true`.
7. No versionar secretos, modelos, datasets generados, outbox, credenciales, claves ni certificados privados.

## Fuentes de verdad

- Spec completa: `PLAN_IMPLEMENTACION_SENTINEL_DNS.md`.
- Índice: `docs/README.md`.
- Arquitectura: `docs/ARCHITECTURE.md`.
- Decisiones: `docs/ADR.md`.
- Tareas: `docs/WORK_PLAN.md`.
- Coordinación: `docs/AGENT_WORKFLOW.md`.
- Cierre: `docs/DEFINITION_OF_DONE.md`.

Si una solicitud cambia privacidad, contratos o componentes, actualizar primero la ADR correspondiente. La solicitud explícita vigente del usuario y la restricción de privacidad tienen prioridad.

## Arquitectura

- Python 3.11, FastAPI y asyncio; Node.js >= 22.17 aloja el worker QVAC.
- Las rutas HTTP validan y delegan; la lógica vive en `app/services/`.
- `app/domain/` no importa FastAPI, Kafka, QVAC, Wazuh, ClickHouse ni SQLite.
- Toda interacción externa implementa un protocolo de `app/domain/ports.py`.
- El SDK QVAC solo se importa desde `app/infrastructure/qvac/`.
- Wazuh recibe eventos por la API local `POST /events`; QoE se escribe en ClickHouse.
- Umbrales y configuración no se hardcodean.

## Flujo del agente

1. Leer estas reglas y los documentos específicos de la tarea.
2. Revisar `git status` y conservar cambios ajenos.
3. Identificar el ID de `docs/WORK_PLAN.md` y limitarse a su alcance.
4. Coordinar antes de editar archivos compartidos: `app/domain/schemas.py`, `app/domain/ports.py`, `app/core/config.py`, `pyproject.toml` y `compose.yaml`.
5. Implementar el corte vertical mínimo que cumpla el criterio de salida.
6. Ejecutar verificaciones proporcionales y reportar comandos/resultados.
7. Entregar el handoff definido en `docs/AGENT_WORKFLOW.md`.

No crear commits, ramas, PR, publicaciones ni despliegues externos salvo solicitud explícita.

## Calidad

- Contratos Pydantic/tipos explícitos entre capas.
- Red con timeout y errores clasificados.
- Side effects idempotentes por `event_id`/`prediction_id`.
- Logs JSON con allowlist; nunca prompts completos, secretos o cuerpos DNS innecesarios.
- Métricas sin `qname`, `client_hash`, `site_id` o `zone_id` como labels.
- Tests deterministas con seed fija.
- No declarar éxito con tests fallando ni ocultar verificaciones no ejecutadas.

## Comandos previstos

Cuando los archivos correspondientes tengan implementación:

- `uv sync --frozen`
- `uv run ruff check .`
- `uv run ruff format --check .`
- `uv run mypy app simulator`
- `uv run pytest tests/unit`
- `uv run pytest tests/integration`
- `docker compose --profile full config`
- `kubectl kustomize deploy/kubernetes/overlays/local`

Si aún no existe la configuración necesaria, documentar el comando como pendiente; no simular éxito.

