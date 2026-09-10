# Runbook de demostración

## Preparación

- Checkout limpio y dependencias precargadas.
- Modelo QVAC disponible localmente.
- Secrets locales configurados.
- Docker Compose full saludable.
- Dashboard Grafana y reglas Wazuh aprovisionados.
- Escenario `mixed_demo` con seed fija.

## Guion máximo 5 minutos

| Tiempo | Acción |
|---:|---|
| 0:00–0:30 | Explicar privacidad y arquitectura. |
| 0:30–1:00 | Mostrar servicios y health checks. |
| 1:00–2:00 | Publicar escenario y mostrar consumer Kafka en vivo. |
| 2:00–3:00 | Mostrar DGA, tunneling, beaconing y typo en Wazuh. |
| 3:00–4:00 | Mostrar QoE, subscores y causa por zona en Grafana. |
| 4:00–4:35 | Interrumpir QVAC y demostrar fallback/alerta. |
| 4:35–5:00 | Mostrar bloqueo de egress, evidencia y repositorio. |

## Verificaciones previas

- [ ] El stream, no el webhook, alimenta la escena principal.
- [ ] Wazuh muestra campos y severidad procesables.
- [ ] Grafana permite filtrar por sitio/zona.
- [ ] El score incluye muestra, tres subscores y causa.
- [ ] QVAC puede detenerse/restaurarse rápidamente.
- [ ] La prueba sin egress está lista.
- [ ] No hay instalaciones ni configuración manual en video.

## Plan de contingencia

- Conservar una seed conocida y timestamps recientes.
- Si un dashboard tarda, consultar primero ClickHouse/Wazuh para demostrar persistencia.
- Si QVAC no inicia, demostrar el modo degradado y la evidencia del smoke previo; registrar la limitación sin ocultarla.
- No usar datos reales para rescatar la demostración.

