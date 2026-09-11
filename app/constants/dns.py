"""DNS event schema and qname limits. Changing these requires an ADR."""

from typing import Final, Literal

SCHEMA_VERSION: Final[Literal["1.0"]] = "1.0"
QNAME_MAX_LENGTH: Final[int] = 253
LABEL_MAX_LENGTH: Final[int] = 63
