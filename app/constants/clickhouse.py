"""Frozen ClickHouse database and QoE table names. Changing these requires an ADR."""

from typing import Final

DATABASE: Final[str] = "sentinel_dns"
QOE_TABLE: Final[str] = "dns_qoe_1m"
