"""HTTP and webhook contract limits. Changing these requires an ADR."""

from typing import Final

PREDICTION_BATCH_MAX: Final[int] = 100
WEBHOOK_TOKEN_HEADER: Final[str] = "X-Sentinel-Token"
WEBHOOK_RETRY_AFTER_SECONDS: Final[int] = 5
PREDICTIONS_PATH: Final[str] = "/api/v1/predictions"
HEALTH_LIVE_PATH: Final[str] = "/health/live"
HEALTH_READY_PATH: Final[str] = "/health/ready"
METRICS_PATH: Final[str] = "/metrics"
