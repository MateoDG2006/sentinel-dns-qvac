"""Stable identifiers for predictions. Changing the namespace reshapes prediction_id."""

from typing import Final
from uuid import NAMESPACE_URL, UUID, uuid5

PREDICTION_ID_NAMESPACE: Final[UUID] = uuid5(NAMESPACE_URL, "https://sentinel-dns.local/prediction")
KAFKA_CONSUMER_ENV: Final[str] = "SENTINEL_ENABLE_KAFKA_CONSUMER"
WAZUH_DISPATCHER_ENV: Final[str] = "SENTINEL_ENABLE_WAZUH_DISPATCHER"
QOE_FLUSH_ENV: Final[str] = "SENTINEL_ENABLE_QOE_FLUSH"
BACKGROUND_POLL_SECONDS: Final[float] = 5.0
