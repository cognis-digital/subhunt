"""Core aggregation engine for SUBHUNT.

Real logic, standard library only. Responsibilities:
  * Parse heterogeneous source files (plain host-per-line, or
    "host,source" / "host source" CSV/whitespace, ignoring comments).
  * Normalize hostnames (strip schemes, ports, wildcards, trailing dots,
    lowercase, IDNA where possible).
  * Validate hostnames per RFC 1123 label rules.
  * Enforce a registrable-domain scope filter.
  * Deduplicate across sources while preserving provenance (which source
    files reported each host) and depth/label statistics.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Iterable

# RFC 1123 label: 1-63 chars, alnum and hyphen, not starting/ending hyphen.
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)


@dataclass
class Subdomain:
    """A single deduplicated subdomain with provenance."""

    host: str
    sources: set[str] = field(default_factory=set)

    @property
    def depth(self) -> int:
        """Number of labels (e.g. a.b.example.com -> 4)."""
        return self.host.count(".") + 1

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "depth": self.depth,
            "sources": sorted(self.sources),
            "source_count": len(self.sources),
        }


@dataclass
class AggregateResult:
    """Result of an aggregation run."""

    scope: str
    subdomains: list[Subdomain] = field(default_factory=list)
    total_lines: int = 0
    invalid: int = 0
    out_of_scope: int = 0
    duplicates: int = 0
    source_files: list[str] = field(default_factory=list)

    @property
    def unique_count(self) -> int:
        return len(self.subdomains)

    def to_dict(self) -> dict:
        return {
            "scope": self.scope,
            "source_files": self.source_files,
            "stats": {
                "total_lines": self.total_lines,
                "unique": self.unique_count,
                "duplicates": self.duplicates,
                "invalid": self.invalid,
                "out_of_scope": self.out_of_scope,
            },
            "subdomains": [s.to_dict() for s in self.subdomains],
        }


def normalize_host(raw: str) -> str | None:
    """Normalize a raw token into a bare hostname, or None if not usable.

    Strips URL scheme, userinfo, path, query, port, wildcard prefixes,
    surrounding whitespace and trailing dots; lowercases; applies IDNA.
    """
    if raw is None:
        return None
    h = raw.strip()
    if not h:
        return None
    # Drop scheme://
    h = _SCHEME_RE.sub("", h)
    # Drop userinfo@
    if "@" in h:
        h = h.split("@", 1)[1]
    # Drop path/query/fragment
    for sep in ("/", "?", "#"):
        if sep in h:
            h = h.split(sep, 1)[0]
    # Drop port (but keep bracketed IPv6 untouched -- we reject those later)
    if h.count(":") == 1 and "]" not in h:
        h = h.split(":", 1)[0]
    # Strip leading wildcard / dot labels: *.example.com, .example.com
    while h.startswith("*.") or h.startswith("."):
        h = h[2:] if h.startswith("*.") else h[1:]
    h = h.rstrip(".").strip().lower()
    if not h:
        return None
    # IDNA encode unicode hostnames to punycode; ignore failures gracefully.
    try:
        h = h.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        # Already-ascii hosts that idna dislikes (e.g. leading digit TLDs)
        # fall through; validity is checked separately.
        pass
    return h or None


def is_valid_hostname(host: str) -> bool:
    """Validate a hostname per RFC 1123 label rules.

    Rejects empty, overlong (>253), single-label, and bare IPv4 addresses
    (we want names, not addresses).
    """
    if not host or len(host) > 253:
        return False
    if "." not in host:
        return False
    labels = host.split(".")
    if any(not _LABEL_RE.match(lbl) for lbl in labels):
        return False
    # Reject bare IPv4 -- all-numeric labels with 4 octets.
    if len(labels) == 4 and all(lbl.isdigit() for lbl in labels):
        return False
    return True


def in_scope(host: str, scope: str) -> bool:
    """True if host equals scope or is a subdomain of scope."""
    scope = scope.strip(".").lower()
    if not scope:
        return True
    return host == scope or host.endswith("." + scope)


def parse_source(text: str) -> list[str]:
    """Extract raw host tokens from a source file's text.

    Supports: one-host-per-line, '#' comments, and lines where the host is
    the first comma- or whitespace-separated field (tool exports often append
    a source/IP column).
    """
    tokens: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # First field, split on comma first, then whitespace.
        field0 = re.split(r"[,\s]+", line, maxsplit=1)[0]
        tokens.append(field0)
    return tokens


def _iter_source_files(paths: Iterable[str]) -> Iterable[tuple[str, str]]:
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                fp = os.path.join(p, name)
                if os.path.isfile(fp):
                    yield fp, _read(fp)
        else:
            yield p, _read(p)


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def aggregate(paths: Iterable[str], scope: str = "") -> AggregateResult:
    """Aggregate, normalize, validate, scope-filter and dedupe.

    `paths` may be files or directories. `scope` (e.g. 'example.com') filters
    to that registrable domain; empty scope keeps everything valid.
    """
    result = AggregateResult(scope=scope.strip(".").lower())
    by_host: dict[str, Subdomain] = {}

    for path, text in _iter_source_files(paths):
        src = os.path.basename(path)
        result.source_files.append(src)
        for raw in parse_source(text):
            result.total_lines += 1
            host = normalize_host(raw)
            if not host or not is_valid_hostname(host):
                result.invalid += 1
                continue
            if scope and not in_scope(host, scope):
                result.out_of_scope += 1
                continue
            existing = by_host.get(host)
            if existing is None:
                by_host[host] = Subdomain(host=host, sources={src})
            else:
                result.duplicates += 1
                existing.sources.add(src)

    result.subdomains = sorted(
        by_host.values(), key=lambda s: (s.depth, s.host)
    )
    return result
