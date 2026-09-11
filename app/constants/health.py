"""Dependency names and readiness details for /health/ready."""

from typing import Final

CONFIG_DEPENDENCY_NAME: Final[str] = "config"
KAFKA_DEPENDENCY_NAME: Final[str] = "kafka"
OUTBOX_DEPENDENCY_NAME: Final[str] = "outbox"
KAFKA_DISABLED_DETAIL: Final[str] = "kafka_consumer_disabled"
KAFKA_CONNECTING_DETAIL: Final[str] = "connecting"
KAFKA_UNAVAILABLE_DETAIL: Final[str] = "consumer_unavailable"
KAFKA_STOPPED_DETAIL: Final[str] = "stopped"
OUTBOX_VOLATILE_DETAIL: Final[str] = "volatile_in_memory"
OUTBOX_SQLITE_DETAIL: Final[str] = "durable_sqlite"
QVAC_FALLBACK_DETAIL: Final[str] = "heuristic_fallback_active"
