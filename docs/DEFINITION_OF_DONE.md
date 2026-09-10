# Definition of Done

## Cualquier tarea

- [ ] Corresponde a un ID de `WORK_PLAN.md`.
- [ ] Respeta capas y ADR.
- [ ] No introduce egress, cloud, secretos ni telemetría externa.
- [ ] Entradas/salidas tienen contratos tipados.
- [ ] Timeouts, errores e idempotencia están cubiertos según riesgo.
- [ ] Tests aplicables pasan y el handoff incluye resultados.
- [ ] No altera cambios ajenos.
- [ ] Actualiza documentación si cambia el comportamiento.

## Seguridad

- [ ] Las cuatro amenazas tienen positivos y negativos.
- [ ] Alertas JSON disparan las reglas Wazuh esperadas.
- [ ] JWT, `401`, `429`, timeout y `5xx` están probados.
- [ ] QVAC caído activa fallback, retry y alerta sin detener Kafka.
- [ ] Duplicados no producen alertas duplicadas observables.

## QoE

- [ ] Ventanas de 60 s por sitio/zona son idempotentes.
- [ ] Score/subscores usan thresholds configurables.
- [ ] Menos de 20 muestras produce `insufficient_data`.
- [ ] Grafana muestra score, subscores, volumen y causa.
- [ ] Una degradación sintética se explica sin consultar código.

## Plataforma

- [ ] Compose full es válido y arranca desde checkout limpio.
- [ ] Dashboards, datasources, tablas y reglas se aprovisionan sin clics.
- [ ] Kustomize, kubeconform y dry-run pasan.
- [ ] No hay `latest`, privilegios ni secretos literales.

## MVP

- [ ] El escenario principal proviene de Kafka.
- [ ] Existe una alerta visible por cada familia de amenaza.
- [ ] ClickHouse/Grafana muestran QoE filtrable por sitio/zona.
- [ ] E2E continúa sin QVAC y se recupera al restaurarlo.
- [ ] La prueba sin egress genera evidencia.
- [ ] README, manifiestos, repositorio y video <5 min están listos.

