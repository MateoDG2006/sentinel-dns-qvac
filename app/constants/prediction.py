"""Stable identifiers for predictions. Changing the namespace reshapes prediction_id."""

from typing import Final
from uuid import NAMESPACE_URL, UUID, uuid5

PREDICTION_ID_NAMESPACE: Final[UUID] = uuid5(NAMESPACE_URL, "https://sentinel-dns.local/prediction")
KAFKA_CONSUMER_ENV: Final[str] = "SENTINEL_ENABLE_KAFKA_CONSUMER"
