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

