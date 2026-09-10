# Plan de trabajo

## Frentes

| Frente | Responsable | Ownership |
|---|---|---|
| A — Backend/IA | Persona A | FastAPI, dominio, features, heurísticas, QVAC y consumer. |
| B — Seguridad/Wazuh | Persona B | Outbox, Wazuh API/RBAC/reglas y privacidad. |
| C — Datos/Plataforma | Persona C | Simulador, QoE, ClickHouse, Grafana, Docker y Kubernetes. |

Los agentes de código adoptan un frente por tarea. No se asignan dos escritores al mismo archivo.

## Backlog

| ID | Estado | Frente | Depende de | Salida |
|---|---|---|---|---|
| A1 | pendiente | A | — | Schemas, ports y config; Ruff/MyPy. |
| A2 | pendiente | A | A1 | FastAPI, auth y webhook 1..100. |
| A3 | pendiente | A | A1 | Features/reglas para cuatro amenazas. |
| A4 | pendiente | A | A3 | Adaptador QVAC y smoke local. |
| A5 | pendiente | A | A2,A4 | Consumer y `PredictionService` compartido. |
| B1 | pendiente | B | A1 | Outbox idempotente y durable. |
| B2 | pendiente | B | B1 | JWT, batches, retry y `429` Wazuh. |
| B3 | pendiente | B | B2 | RBAC/reglas y alerta visible. |
| B4 | pendiente | B | A4 | Prueba sin egress y evidencia. |
| C1 | pendiente | C | A1 | Kafka local y simulador determinista. |
| C2 | pendiente | C | A1 | Agregador QoE con tests. |
| C3 | pendiente | C | C2 | ClickHouse/Grafana aprovisionados. |
| C4 | pendiente | C | A5,B3,C3 | Compose full con un comando. |
| C5 | pendiente | C | C4 | Kustomize, kubeconform y dry-run. |
| I1 | pendiente | todos | A5,B3,C4 | E2E mixed, fallback y recuperación. |
| I2 | pendiente | todos | I1 | README y video <5 min. |

Estados: `pendiente`, `en_curso`, `bloqueada`, `en_revision`, `terminada`.

## Archivos compartidos

- A crea `schemas.py`, `ports.py`, `config.py` y `pyproject.toml`.
- C integra `compose.yaml`.
- Cambios posteriores requieren coordinación y revisión cruzada.

## Gates

1. Contratos revisados por dos frentes.
2. Evento Kafka genera predicción.
3. Alerta high visible en Wazuh.
4. Grafana explica zona degradada.
5. E2E funciona sin egress.
6. Compose, Kubernetes, README y video listos.

