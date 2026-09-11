"""HTTP and webhook contract limits. Changing these requires an ADR."""

from typing import Final

PREDICTION_BATCH_MAX: Final[int] = 100
WEBHOOK_TOKEN_HEADER: Final[str] = "X-Sentinel-Token"
WEBHOOK_RETRY_AFTER_SECONDS: Final[int] = 5
PREDICTIONS_PATH: Final[str] = "/api/v1/predictions"
LAB_PATH: Final[str] = "/lab"
LAB_CATALOG_PATH: Final[str] = "/api/v1/lab/catalog"
LAB_EVALUATE_PATH: Final[str] = "/api/v1/lab/evaluate"
HEALTH_LIVE_PATH: Final[str] = "/health/live"
HEALTH_READY_PATH: Final[str] = "/health/ready"
METRICS_PATH: Final[str] = "/metrics"
DOCS_PATH: Final[str] = "/docs"
REDOC_PATH: Final[str] = "/redoc"
OPENAPI_PATH: Final[str] = "/openapi.json"
