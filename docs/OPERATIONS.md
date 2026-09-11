# Operación local

## Entornos

- Docker Compose: entorno ejecutable y canónico de demo.
- Kubernetes: manifiestos renderizados y validados; no se exige despliegue.

## Servicios previstos

Kafka/KRaft, inicializador de topics, Sentinel API/consumer/QVAC, productor sintético, ClickHouse, Grafana, Prometheus, Wazuh manager, indexer y dashboard.

## Arranque objetivo

1. Preparar el modelo QVAC en el volumen local.
2. Configurar secretos fuera de Git.
3. Levantar el profile `full`.
4. Esperar health checks.
5. Ejecutar smoke test.
6. Activar el escenario sintético de demo.

Los comandos exactos se completarán cuando `compose.yaml`, scripts y README tengan implementación. No documentar comandos que todavía no funcionen.

## LogoDNSQueries

- Dataset crudo (opcional): `data/LogoDNSQueries/*.csv|json|jsonl` — gitignorado; no versionar dumps.
- Fixtures curadas: `tests/fixtures/dns/` (allowlist sintético `.test`).
- Cargador: `uv run python -m simulator.logo_dns_queries`.
- Lab: escenario `logo_dns` en `POST /api/v1/lab/evaluate`. El ground truth va en sidecar, no en `NormalizedDnsEvent`.

## Salud

- `/health/live`: proceso/event loop.
- `/health/ready`: Kafka, outbox y configuración listos.
- QVAC degradado no invalida readiness si funciona el fallback.
- `/metrics`: métricas agregadas sin datos DNS sensibles.

## Degradación

| Falla | Respuesta |
|---|---|
| QVAC timeout/caído | Fallback heurístico, retry y alerta técnica agregada. |
| Wazuh caído | Outbox durable y entrega al recuperarse. |
| Wazuh `401` | Renovar JWT una vez. |
| Wazuh `429` | Respetar `Retry-After` y aplicar jitter. |
| ClickHouse caído | Reintentar ventana idempotente; no inventar score. |
| Outbox lleno | Pausar Kafka y devolver `429` al webhook. |
| Evento inválido | DLQ local con razón; continuar partición. |

## Recuperación

Al reiniciar, Sentinel reanuda offsets y outbox sin duplicados observables. La recuperación de QVAC debe retirar el estado degradado y conservar la alerta previa como evidencia.

## Kubernetes

Validar render Kustomize, esquemas con kubeconform, dry-run del cliente y ausencia de LoadBalancer, `latest`, privilegios o secretos literales.

