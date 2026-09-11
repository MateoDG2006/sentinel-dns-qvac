"""Defaults for the local QVAC fidelity lab. Not production traffic."""

from typing import Final

from app.constants.api import PREDICTION_BATCH_MAX

DEFAULT_SEED: Final[int] = 42
DEFAULT_LIMIT: Final[int] = 12
MAX_LIMIT: Final[int] = PREDICTION_BATCH_MAX
DEFAULT_DURATION_S: Final[float] = 8.0
MAX_DURATION_S: Final[float] = 30.0
LOGO_DNS_DESCRIPTION: Final[str] = (
    "Fixtures LogoDNSQueries (tests/fixtures/dns + data/LogoDNSQueries)"
)
THREAT_ORDER: Final[tuple[str, ...]] = (
    "none",
    "dga",
    "typosquatting",
    "dns_tunneling",
    "beaconing",
)
