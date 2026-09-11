"""LogoDNSQueries fixture paths and stable event IDs. Not a DNS wire contract."""

from pathlib import Path
from typing import Final
from uuid import NAMESPACE_URL, UUID, uuid5

SCENARIO_NAME: Final[str] = "logo_dns"
SOURCE_DIRNAME: Final[str] = "LogoDNSQueries"
CURATED_RELATIVE: Final[Path] = Path("tests") / "fixtures" / "dns"
ALLOWED_SUFFIXES: Final[tuple[str, ...]] = (".json", ".jsonl", ".csv")
DEFAULT_SITE_ID: Final[str] = "lab-1"
DEFAULT_ZONE_ID: Final[str] = "zone-a"
DEFAULT_RESOLVER_ID: Final[str] = "resolver-lab-1"
DEFAULT_CLIENT_HASH: Final[str] = "logo-dns-client"
EVENT_ID_NAMESPACE: Final[UUID] = uuid5(
    NAMESPACE_URL, "https://sentinel-dns.local/logo-dns-queries"
)
GROUND_TRUTH_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "threat_type",
        "technique",
        "scenario",
        "target_brand",
        "expected_threat",
        "label",
        "ground_truth",
    }
)
QNAME_ALIASES: Final[tuple[str, ...]] = ("qname", "domain", "name", "query")
