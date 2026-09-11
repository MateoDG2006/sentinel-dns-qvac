# Grafana con el plugin de ClickHouse incorporado en la imagen.
#
# El plugin se descarga UNA vez, al construir la imagen (fase de bootstrap, con
# red). En runtime Grafana no descarga nada, así la demo funciona con la salida
# a Internet bloqueada (spec sección 13). Con GF_INSTALL_PLUGINS el plugin se
# bajaría en cada arranque, y sin Internet el dashboard quedaría sin datasource.
#
# Versiones fijadas a propósito:
# - El plugin 4.15 en adelante exige Grafana >= 11.6. La 4.14.0 es la última
#   compatible con Grafana 11.2, que es la versión contra la que se verificó el
#   dashboard.
# - Actualizar Grafana obliga a re-verificar los 8 paneles.

FROM grafana/grafana:11.2.0

ARG CLICKHOUSE_PLUGIN_VERSION=4.14.0

# Los plugins van fuera de /var/lib/grafana: ahí se monta el volumen de datos,
# que taparía cualquier plugin instalado en la imagen.
ENV GF_PATHS_PLUGINS=/var/lib/grafana-plugins

USER root
RUN mkdir -p "$GF_PATHS_PLUGINS" \
    && grafana cli --pluginsDir "$GF_PATHS_PLUGINS" \
        plugins install grafana-clickhouse-datasource "$CLICKHOUSE_PLUGIN_VERSION" \
    && chown -R 472:0 "$GF_PATHS_PLUGINS"
USER 472
