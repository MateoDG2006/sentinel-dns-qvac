# Documentación de Sentinel-DNS

Este directorio convierte la definición del proyecto en contexto operativo para personas y agentes.

## Orden de lectura

1. [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md): problema, alcance y éxito esperado.
2. [`TECH_SPEC.md`](TECH_SPEC.md): entrada estable a la spec canónica.
3. [`ARCHITECTURE.md`](ARCHITECTURE.md): componentes, flujos y límites.
4. [`ADR.md`](ADR.md): decisiones que no deben reinterpretarse.
5. [`WORK_PLAN.md`](WORK_PLAN.md): tareas, dependencias y reparto.
6. [`AGENT_WORKFLOW.md`](AGENT_WORKFLOW.md): coordinación y handoffs.
7. [`DEFINITION_OF_DONE.md`](DEFINITION_OF_DONE.md): criterios de cierre.
8. [`PRIVACY_PROOF.md`](PRIVACY_PROOF.md): controles sin egress.
9. [`OPERATIONS.md`](OPERATIONS.md): operación y degradación.
10. [`DEMO_RUNBOOK.md`](DEMO_RUNBOOK.md): demostración reproducible.

La especificación detallada permanece en [`../PLAN_IMPLEMENTACION_SENTINEL_DNS.md`](../PLAN_IMPLEMENTACION_SENTINEL_DNS.md).

## Mantenimiento

- Alcance: actualizar `PROJECT_CONTEXT.md` y la spec.
- Arquitectura: registrar primero una ADR.
- Tareas: actualizar `WORK_PLAN.md`.
- Privacidad: actualizar `PRIVACY_PROOF.md` y sus verificaciones.
- Operación/demo: mantener `OPERATIONS.md` y `DEMO_RUNBOOK.md` sincronizados.
