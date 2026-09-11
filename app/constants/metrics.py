"""Prometheus metric names. Changing these requires an ADR."""

from typing import Final

EVENTS_TOTAL: Final[str] = "sentinel_dns_events_total"
PREDICTIONS_TOTAL: Final[str] = "sentinel_dns_predictions_total"
PROCESSING_SECONDS: Final[str] = "sentinel_dns_processing_seconds"
QVAC_SECONDS: Final[str] = "sentinel_dns_qvac_seconds"
QVAC_AVAILABLE: Final[str] = "sentinel_dns_qvac_available"
KAFKA_CONSUMER_LAG: Final[str] = "sentinel_dns_kafka_consumer_lag"
OUTBOX_PENDING: Final[str] = "sentinel_dns_outbox_pending"
WAZUH_DELIVERY_TOTAL: Final[str] = "sentinel_dns_wazuh_delivery_total"
QOE_FLUSH_TOTAL: Final[str] = "sentinel_dns_qoe_flush_total"
FORBIDDEN_LABELS: Final[frozenset[str]] = frozenset({"qname", "client_hash", "site_id", "zone_id"})
