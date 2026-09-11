"""Frozen Kafka topic names. Changing these requires an ADR."""

from typing import Final

TOPIC_NORMALIZED: Final[str] = "dns.telemetry.normalized"
TOPIC_DLQ: Final[str] = "sentinel.dns.dlq"
TOPIC_GROUNDTRUTH: Final[str] = "sentinel.dns.groundtruth"
