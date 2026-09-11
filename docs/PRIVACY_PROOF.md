# Prueba de privacidad y operación local

## Afirmación verificable

Sentinel-DNS procesa consultas y derivados dentro del host o clúster local. La inferencia QVAC, alertas Wazuh, persistencia ClickHouse, paneles Grafana y métricas Prometheus no requieren endpoints externos durante runtime.

## Controles requeridos

- Modelo QVAC precargado y montado read-only.
- `QVAC_CACHE_DIR` apunta a almacenamiento local.
- Descarga de modelos separada del runtime.
- Red Docker interna para Kafka, Wazuh, ClickHouse y Prometheus.
- Solo FastAPI y dashboards se publican al host cuando la demo lo exige.
- Kubernetes usa default-deny egress y allowlists internas.
- TLS y CA local para Wazuh; secretos montados, nunca versionados.
- Logs por allowlist sin prompts completos, secretos ni cuerpos DNS.
- Métricas agregadas sin dominios o IDs de cliente como labels.

## Procedimiento de evidencia

`scripts/prove_no_egress.py` deberá:

1. Confirmar hash y ubicación local del modelo/configuración.
2. Ejecutar inferencia con salida a Internet bloqueada.
3. Confirmar acceso interno a Kafka, ClickHouse y Wazuh.
4. Comprobar que una conexión pública controlada falla.
5. Confirmar que la predicción y alerta se completan.
6. Guardar timestamp, hashes, estado de red y resultados en un artefacto.

## Checklist de revisión

- [ ] No hay dominios de servicios cloud en código/configuración.
- [ ] No existen API keys externas.
- [ ] La imagen no descarga modelos al iniciar.
- [ ] Los logs no contienen el prompt QVAC.
- [ ] El escenario E2E pasa sin egress.
- [ ] La evidencia se puede mostrar en el video.


## Resultado (WBS B4, 2026-09-11)

`scripts/prove_no_egress.py` se ejecutó con la red física desconectada (adaptador apagado, no una regla de firewall):

- Modelo local: `Qwen3-0.6B-Q4_0.gguf`, hash SHA-256 registrado en el artefacto de evidencia.
- Intento de conexión pública real a 8.8.8.8:53 -> falló (`OSError [WinError 10065] unreachable host`).
- Inferencia QVAC real (`QvacClient.start` + `enrich`) completada sin red, en frío, con timeout ampliado solo para este script (ver comentario `PROOF_INFERENCE_TIMEOUT_SECONDS` en el script; `qvac_timeout_seconds` de producción no se tocó).
- Evidencia completa: `docs/evidence/no_egress_20260911T054837Z.txt` (timestamp, hash del modelo, hash de la config, resultado de la sonda de conexión, veredicto real del modelo).

### Alcance de esta corrida

Cubre únicamente el camino de inferencia QVAC. No incluye una verificación del acceso interno a Kafka/ClickHouse/Wazuh (esos servicios no corren aún en este entorno -- pendiente de C4/compose.yaml), ni el escenario E2E completo.

### Checklist de revisión (actualizado)

- [x] No hay dominios de servicios cloud en código/configuración.
- [x] No existen API keys externas.
- [x] La imagen no descarga modelos al iniciar (bootstrap es un paso separado y explícito, con red).
- [ ] Los logs no contienen el prompt QVAC -- verificado solo en la salida de este script, no auditado en el resto del sistema.
- [ ] El escenario E2E pasa sin egress -- solo se probó el camino de inferencia QVAC, no Kafka/Wazuh/ClickHouse end-to-end.
- [x] La evidencia se puede mostrar en el video.