"""HTTP and webhook contract limits. Changing these requires an ADR."""

from typing import Final

PREDICTION_BATCH_MAX: Final[int] = 100
