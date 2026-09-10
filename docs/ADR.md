# Registro de decisiones arquitectónicas

Todas las decisiones listadas están **aceptadas**.

| ID | Decisión | Consecuencia |
|---|---|---|
| ADR-001 | Servicio Python modular con FastAPI/asyncio | Un artefacto y capas estrictas. |
| ADR-002 | Kafka principal; webhook secundario | La demo acredita procesamiento real del stream. |
| ADR-003 | Detección híbrida | Heurísticas para todos; QVAC para candidatos. |
| ADR-004 | `QvacInferencePort` aísla el SDK | Solo el adaptador conoce QVAC. |
| ADR-005 | Completion QVAC con JSON validado | No confundir `classify` de imagen con dominios. |
| ADR-006 | Wazuh ingresa por `POST /events` | JWT, lotes de hasta 100 y rate limiting. |
| ADR-007 | SQLite como outbox | Retries durables y commits Kafka seguros. |
| ADR-008 | QoE en ventanas de 60 s | Score explicable e idempotente. |
| ADR-009 | Docker Compose como demo canónica | Stack completo local. |
| ADR-010 | Kubernetes solo requiere validación | Se prioriza el MVP ejecutable. |
| ADR-011 | QVAC tiene modo degradado | Heurísticas, retry y alerta operativa. |
| ADR-012 | Runtime sin egress | Modelo local y prueba verificable. |

## Nueva decisión

Agregar una fila como `propuesta` y documentar contexto, opciones, elección, impacto de privacidad, contratos, migración y validación. Cambios en schemas, persistencia o flujo requieren revisión de otro workstream.

