"""Hosts and suffixes treated as local for no-egress endpoint checks."""

from typing import Final

LOCAL_SERVICE_HOSTS: Final[frozenset[str]] = frozenset(
    {
        "localhost",
        "host.docker.internal",
        "kafka",
        "clickhouse",
        "grafana",
        "prometheus",
        "wazuh-manager",
        "wazuh-indexer",
        "wazuh-dashboard",
        "sentinel-api",
        "synthetic-producer",
    }
)
LOCAL_DNS_SUFFIXES: Final[tuple[str, ...]] = (
    ".local",
    ".internal",
    ".localhost",
    ".sentinel-net",
)
