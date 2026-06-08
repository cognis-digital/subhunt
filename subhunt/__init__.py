"""SUBHUNT - aggregate & dedupe subdomain enumeration from multiple sources.

Defensive / authorized-testing tool. It ingests subdomain lists produced by
different enumeration tools (subfinder, amass, assetfinder, crt.sh dumps, etc.)
and merges them into one clean, deduplicated, validated subdomain set.

No network, no active probing, no attack capability -- pure offline
aggregation, normalization and reporting.
"""
from .core import (
    Subdomain,
    AggregateResult,
    normalize_host,
    is_valid_hostname,
    in_scope,
    parse_source,
    aggregate,
)

TOOL_NAME = "subhunt"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Subdomain",
    "AggregateResult",
    "normalize_host",
    "is_valid_hostname",
    "in_scope",
    "parse_source",
    "aggregate",
    "TOOL_NAME",
    "TOOL_VERSION",
]
