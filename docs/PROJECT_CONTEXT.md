# Contexto del proyecto

## Problema

Ovnicom opera infraestructura de red y datacenter para clientes regulados de banca, gobierno y salud en Panamá, Colombia, Guatemala y El Salvador. El pipeline DNS usa BIND9/dnstap, Vector, Kafka, ClickHouse, Grafana y Wazuh.

El tráfico DNS revela hábitos de personas y empresas. Ninguna consulta ni dato derivado puede salir del datacenter, incluido cualquier endpoint de inferencia cloud.

## Producto

Sentinel-DNS será un consumidor adicional de Kafka con dos salidas:

1. **Seguridad:** DGA, typosquatting, DNS tunneling y beaconing/C2 hacia Wazuh.
2. **Experiencia:** score QoE por sitio/zona mediante latencia, NXDOMAIN y saturación hacia ClickHouse/Grafana.

FastAPI ofrece un webhook local y salud/métricas. QVAC ejecuta inferencia local. Las heurísticas cubren el hot path y mantienen el servicio cuando QVAC falla.

## Restricciones confirmadas

- Repositorio nuevo y equipo de tres personas.
- Stack completo local con Docker Compose.
- Kubernetes se entrega como manifiestos validados, sin ejecutar el clúster.
- Volumen de eventos desconocido: medir antes de prometer capacidad.
- Datos exclusivamente sintéticos.
- QVAC fallido implica heurísticas, retry y alerta técnica Wazuh.

## Qué valora el jurado

- Clasificación sobre Kafka, no un archivo estático.
- Alertas procesables por Wazuh.
- QoE comprensible para un operador.
- Evidencia de que ningún dato sale.
- Repositorio reproducible y video menor a cinco minutos.

## Fuera de alcance

- Datos reales, entrenamiento desde cero y bloqueo automático en BIND9.
- Alta disponibilidad y autoscaling calibrado con tráfico real.
- APIs públicas de reputación o inferencia remota.
- Modificar el pipeline productivo existente.

