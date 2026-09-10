# Sentinel-DNS

Inteligencia local sobre telemetría DNS para detectar amenazas y medir la calidad de experiencia sin enviar consultas ni datos derivados fuera del datacenter.

> **Estado:** estructura y documentación inicial. La aplicación y el stack Docker/Kubernetes todavía están en implementación; consulta el [plan de trabajo](docs/WORK_PLAN.md).

## Problema

Ovnicom opera infraestructura de red para clientes regulados de banca, gobierno y salud. Las consultas DNS permiten detectar actividad maliciosa y problemas de resolución, pero también revelan hábitos de navegación. Por esa razón, el procesamiento y la inferencia deben permanecer íntegramente dentro de la infraestructura local.

Sentinel-DNS se conecta como consumidor adicional del stream existente y produce dos resultados:

- **Seguridad:** detección en tiempo real de DGA, typosquatting, DNS tunneling y beaconing/C2, con alertas procesables en Wazuh.
- **Experiencia:** score QoE por sitio y zona basado en latencia, NXDOMAIN y saturación, almacenado en ClickHouse y visualizado en Grafana.

## Principio de privacidad

```text
Consultas DNS + datos derivados + inferencia = infraestructura local
```

- QVAC ejecuta el modelo en el host local.
- No se permiten APIs de inferencia, reputación o telemetría en la nube.
- El modelo se prepara antes del runtime y se monta desde almacenamiento local.
- El entorno de demostración debe funcionar con salida a Internet bloqueada.
- Solo se utilizan datos sintéticos.

La estrategia verificable está documentada en [PRIVACY_PROOF.md](docs/PRIVACY_PROOF.md).

## Arquitectura

```mermaid
flowchart LR
    B[BIND9 + dnstap] --> V[Vector] --> K[(Kafka)]
    K --> C[(ClickHouse existente)]
    K --> S[Sentinel-DNS<br/>FastAPI + consumer]
    H[Webhook local] --> S
    S --> R[Features + heurísticas]
    R --> Q[QVAC local]
    Q -. fallback .-> R
    R --> O[(Outbox SQLite)] --> W[Wazuh]
    S --> E[QoE 60 s] --> CH[(ClickHouse QoE)] --> G[Grafana]
    S --> P[Prometheus]
```

Kafka es la fuente principal. El webhook FastAPI utiliza el mismo servicio de predicción y existe para integración y pruebas; no sustituye el procesamiento del stream.

### Detección híbrida

1. Las heurísticas analizan todos los eventos con baja latencia.
2. QVAC local confirma o enriquece candidatos ambiguos.
3. Si QVAC falla, continúan las heurísticas, se programa el reintento y Wazuh recibe una alerta técnica.
4. Una outbox local permite reintentos e idempotencia durante fallos de Wazuh.

## Stack

| Componente | Tecnología | Responsabilidad |
|---|---|---|
| API y agente | Python 3.11, FastAPI, asyncio | Webhook, consumer y orquestación. |
| Inferencia | QVAC Python SDK + worker Node.js | Inferencia local con modelo ligero. |
| Stream | Kafka | Telemetría DNS normalizada. |
| Seguridad | Wazuh | Reglas, severidad, correlación y alertas. |
| Analítica | ClickHouse | Ventanas y score QoE. |
| Visualización | Grafana | Dashboard por sitio y zona. |
| Observabilidad | Prometheus | Salud y métricas técnicas agregadas. |
| Resiliencia | SQLite | Outbox y reintentos locales. |
| Entorno local | Docker Compose | Stack ejecutable de desarrollo/demo. |
| Despliegue declarativo | Kubernetes + Kustomize | Manifiestos validados. |

## Estructura

```text
app/
├── api/                 # FastAPI, dependencias y rutas
├── core/                # Configuración, lifecycle, seguridad y logging
├── domain/              # Schemas, enums, errores y ports
├── services/            # Predicción, heurísticas, QoE y outbox
├── infrastructure/      # Kafka, QVAC, Wazuh, ClickHouse y SQLite
└── observability/       # Health checks y métricas

simulator/               # Generador de tráfico DNS sintético
config/                  # Umbrales de detección y QoE
deploy/                  # Docker, Kubernetes y provisioning
scripts/                 # Bootstrap, smoke, privacidad y validación
tests/                   # Unitarias, integración, E2E y fixtures
docs/                    # Arquitectura, ADR, operación y coordinación
```

## Estado de implementación

- [x] Especificación técnica y decisiones arquitectónicas.
- [x] Estructura inicial del repositorio.
- [x] Reglas para trabajo con agentes.
- [ ] Contratos de dominio y configuración.
- [ ] FastAPI y webhook `POST /api/v1/predictions`.
- [ ] Consumer Kafka y simulador sintético.
- [ ] Features, heurísticas y adaptador QVAC.
- [ ] Outbox e integración Wazuh.
- [ ] QoE, ClickHouse y Grafana.
- [ ] Docker Compose ejecutable.
- [ ] Manifiestos Kubernetes validados.
- [ ] Pruebas E2E y evidencia sin egress.

## Desarrollo local

### Requisitos previstos

- Python 3.11.
- Node.js 22.17 o superior para el worker QVAC.
- `uv` para dependencias Python.
- Docker con Docker Compose.
- `kubectl`, Kustomize y kubeconform para validar Kubernetes.
- Recursos suficientes para Kafka, ClickHouse y el stack completo de Wazuh.

### Situación actual

`pyproject.toml`, `compose.yaml`, `Dockerfile`, `.env.example` y los scripts son placeholders. El quickstart ejecutable se añadirá al completar las tareas A1 y C4 del [plan](docs/WORK_PLAN.md). No se debe interpretar el scaffold como una aplicación funcional.

### Flujo objetivo

Cuando la implementación esté disponible, el proceso será:

1. Copiar `.env.example` a un archivo local no versionado y configurar secretos.
2. Preparar el modelo QVAC en un volumen local.
3. Instalar las dependencias bloqueadas con `uv`.
4. Levantar el profile Docker Compose `full`.
5. Ejecutar el smoke test y el escenario sintético `mixed_demo`.
6. Abrir Wazuh y Grafana para comprobar alertas y QoE.
7. Ejecutar la prueba sin egress.

Los comandos se publicarán en [OPERATIONS.md](docs/OPERATIONS.md) únicamente cuando hayan sido probados.

## API prevista

| Método | Ruta | Uso |
|---|---|---|
| `POST` | `/api/v1/predictions` | Acepta 1–100 eventos sintéticos y responde `202`. |
| `GET` | `/health/live` | Estado del proceso y event loop. |
| `GET` | `/health/ready` | Kafka, outbox y configuración disponibles. |
| `GET` | `/metrics` | Métricas Prometheus sin datos DNS sensibles. |

El webhook utilizará `X-Sentinel-Token`. La entrega a Wazuh será asíncrona mediante su API local `POST /events` con JWT y lotes.

## Datos sintéticos

El simulador cubrirá escenarios reproducibles con seed fija:

- tráfico normal;
- ráfaga DGA;
- typosquatting sobre marcas ficticias;
- tunneling mediante subdominios largos y consultas TXT;
- beaconing periódico;
- latencia elevada, NXDOMAIN y saturación por zona;
- escenario combinado para la demostración.

Cada evento del hackathon debe declarar `synthetic=true`. El ground truth se mantiene separado del evento consumido por el detector.

## Trabajo con agentes

Los agentes deben comenzar leyendo [AGENTS.md](AGENTS.md) y tomar una tarea identificada en [WORK_PLAN.md](docs/WORK_PLAN.md). El proyecto se divide en tres frentes:

- **A — Backend/IA:** FastAPI, dominio, heurísticas, QVAC y consumer.
- **B — Seguridad/Wazuh:** outbox, API/RBAC/reglas y privacidad.
- **C — Datos/Plataforma:** simulador, QoE, ClickHouse, Grafana, Docker y Kubernetes.

El protocolo de ownership, revisión y handoff está en [AGENT_WORKFLOW.md](docs/AGENT_WORKFLOW.md). Los criterios obligatorios de cierre están en [DEFINITION_OF_DONE.md](docs/DEFINITION_OF_DONE.md).

## Documentación

- [Especificación completa](PLAN_IMPLEMENTACION_SENTINEL_DNS.md)
- [Índice documental](docs/README.md)
- [Contexto del proyecto](docs/PROJECT_CONTEXT.md)
- [Arquitectura](docs/ARCHITECTURE.md)
- [Decisiones arquitectónicas](docs/ADR.md)
- [Plan de trabajo](docs/WORK_PLAN.md)
- [Privacidad y no egress](docs/PRIVACY_PROOF.md)
- [Operación](docs/OPERATIONS.md)
- [Runbook de demostración](docs/DEMO_RUNBOOK.md)

## Criterios principales del MVP

- La clasificación funciona sobre Kafka.
- Las cuatro familias de amenaza aparecen como alertas procesables en Wazuh.
- El score QoE es interpretable y filtrable por sitio/zona en Grafana.
- La interrupción de QVAC activa fallback sin detener el stream.
- La demo completa funciona sin salida a Internet.
- Docker Compose se levanta de forma reproducible.
- Los manifiestos Kubernetes pasan render, validación de esquema y dry-run.

## Referencias

- [QVAC Python SDK](https://docs.qvac.tether.io/python-sdk/)
- [Requisitos de QVAC](https://docs.qvac.tether.io/system-requirements/)
- [Wazuh API](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [Decodificador JSON de Wazuh](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html)

## Licencia

Pendiente de definición por el equipo antes de publicar el repositorio.
