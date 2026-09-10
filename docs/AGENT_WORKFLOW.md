# Flujo de trabajo con agentes

## Inicio

El coordinador entrega al agente el ID de `WORK_PLAN.md`, objetivo, criterio de salida, rutas permitidas, archivos compartidos prohibidos y dependencias disponibles.

El agente lee `AGENTS.md`, la spec y los documentos de su tarea; después revisa `git status` y reporta solapamientos antes de editar.

## Paralelización

- Delegar solo subtareas independientes y acotadas.
- Un archivo tiene un único escritor activo.
- No cambiar contratos para facilitar una implementación local.
- B y C consumen los ports de A; si falta uno, proponen la firma antes de crear alternativas.
- C integra `compose.yaml`; A/B solicitan los cambios necesarios.
- Se pueden ejecutar tests de otro frente, pero no modificarlo sin coordinación.
- Preservar cambios ajenos, incluso incompletos.

## Tamaño de tarea

Cada tarea debe producir una unidad revisable de 1–4 horas con resultado observable. Dividir por cortes verticales.

Ejemplos adecuados:

- Implementar schema DNS y normalización IDN con tests.
- Implementar renovación JWT y envío batch Wazuh con servidor fake.
- Crear tabla QoE y consulta utilizada por un panel Grafana.

## Handoff obligatorio

```text
Tarea: <ID>
Estado: terminada | en_revision | bloqueada
Resultado: <qué funciona>
Archivos: <creados/modificados>
Contratos: <sin cambios | cambios acordados>
Verificación:
  - <comando> -> <resultado>
Pendientes/riesgos: <lista o ninguno>
Siguiente tarea desbloqueada: <ID o ninguna>
```

No escribir “todo funciona” sin evidencia. Si una prueba no se ejecutó, indicarlo y explicar qué falta.

## Revisión cruzada

- A revisa contratos, asincronía y acoplamiento.
- B revisa secretos, logs, red, autenticación y datos expuestos.
- C revisa reproducibilidad, contenedores, health checks y provisioning.
- El autor corrige; el revisor no reescribe todo el frente salvo reasignación.

## Conflictos

1. Detener solo el archivo en conflicto y continuar trabajo independiente.
2. Presentar rutas, contrato afectado, error y alternativas.
3. Registrar ADR si afecta arquitectura o privacidad.
4. No resolver con reset, checkout destructivo ni sobrescritura.

## Prompt de asignación

```text
Implementa la tarea <ID> de docs/WORK_PLAN.md. Lee AGENTS.md, la spec y docs/AGENT_WORKFLOW.md. Limita cambios a <rutas>. No edites <archivos compartidos>. Ejecuta las verificaciones del criterio de salida y termina con el handoff requerido.
```

