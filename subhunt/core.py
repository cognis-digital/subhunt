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

import json
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

    @property
    def source_count(self) -> int:
        """Number of distinct source files that reported this host."""
        return len(self.sources)

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


def normalize_host(raw) -> str | None:
    """Normalize a raw token into a bare hostname, or None if not usable.

    Strips URL scheme, userinfo, path, query, port, wildcard prefixes,
    surrounding whitespace and trailing dots; lowercases; applies IDNA.
    Accepts any input type; non-string inputs are coerced to str or rejected.
    """
    if raw is None:
        return None
    # Accept only str-like; coerce bytes, reject anything else silently.
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8", errors="replace")
        except Exception:
            return None
    elif not isinstance(raw, str):
        try:
            raw = str(raw)
        except Exception:
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
    if not host or not isinstance(host, str) or len(host) > 253:
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
    if not scope or not isinstance(scope, str):
        return True
    scope = scope.strip().strip(".").lower()
    if not scope:
        return True
    if not host or not isinstance(host, str):
        return False
    return host == scope or host.endswith("." + scope)


def parse_source(text: str) -> list[str]:
    """Extract raw host tokens from a source file's text.

    Supports: one-host-per-line, '#' comments, and lines where the host is
    the first comma- or whitespace-separated field (tool exports often append
    a source/IP column).
    Returns an empty list for empty or non-string input.
    """
    if not text or not isinstance(text, str):
        return []
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
    """Yield (filepath, text) for each readable file in paths.

    Raises ValueError for paths that do not exist, so callers get a clear
    message rather than a raw OSError traceback.
    """
    for p in paths:
        if not isinstance(p, str):
            raise ValueError(f"path must be a string, got {type(p).__name__!r}")
        if os.path.isdir(p):
            entries = sorted(os.listdir(p))
            for name in entries:
                fp = os.path.join(p, name)
                if os.path.isfile(fp):
                    yield fp, _read(fp)
        elif os.path.isfile(p):
            yield p, _read(p)
        else:
            raise ValueError(f"no such file or directory: {p!r}")


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as exc:
        raise OSError(f"cannot read {path!r}: {exc.strerror}") from exc


def aggregate(paths: Iterable[str], scope: str = "") -> AggregateResult:
    """Aggregate, normalize, validate, scope-filter and dedupe.

    `paths` may be files or directories. `scope` (e.g. 'example.com') filters
    to that registrable domain; empty scope keeps everything valid.

    Raises ValueError for missing/invalid paths.
    Raises TypeError if paths is None.
    """
    if paths is None:
        raise TypeError("paths must be an iterable, got None")
    scope_clean = scope.strip().strip(".").lower() if isinstance(scope, str) else ""
    result = AggregateResult(scope=scope_clean)
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
            if scope_clean and not in_scope(host, scope_clean):
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


def scan(target: str) -> AggregateResult:
    """High-level alias: aggregate a single path (file or directory).

    Provided for MCP server and other callers that prefer a simpler API.
    Raises ValueError if target is missing or invalid.
    """
    if not target or not isinstance(target, str):
        raise ValueError("target must be a non-empty string")
    return aggregate([target])


def to_json(result: AggregateResult) -> str:
    """Serialize an AggregateResult to a JSON string."""
    if not isinstance(result, AggregateResult):
        raise TypeError(f"expected AggregateResult, got {type(result).__name__!r}")
    return json.dumps(result.to_dict(), indent=2, sort_keys=True)
