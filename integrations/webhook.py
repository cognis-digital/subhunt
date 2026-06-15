#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Forward SUBHUNT JSON findings to a webhook URL.",
    )
    ap.add_argument("--url", required=True, help="Destination URL (https://...)")
    ap.add_argument("--header", action="append", default=[], help="Extra header as 'Key: Value'")
    ap.add_argument("--timeout", type=int, default=15, help="HTTP timeout in seconds (default: 15)")
    args = ap.parse_args()

    # Validate URL scheme to avoid obvious mistakes.
    if not args.url.startswith(("http://", "https://")):
        print("webhook: error: URL must start with http:// or https://", file=sys.stderr)
        return 2

    # Validate timeout range.
    if args.timeout < 1 or args.timeout > 300:
        print("webhook: error: --timeout must be between 1 and 300 seconds", file=sys.stderr)
        return 2

    # Read and validate stdin payload.
    try:
        raw = sys.stdin.read()
    except OSError as exc:
        print(f"webhook: error reading stdin: {exc}", file=sys.stderr)
        return 2

    if not raw or not raw.strip():
        print("webhook: error: empty payload on stdin — nothing to forward", file=sys.stderr)
        return 2

    # Best-effort JSON validation — warn but still forward if it parses badly.
    try:
        json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"webhook: warning: stdin is not valid JSON ({exc}); forwarding anyway", file=sys.stderr)

    payload = raw.encode("utf-8")
    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")

    # Parse and attach extra headers; skip malformed ones with a warning.
    for h in args.header:
        if ":" not in h:
            print(f"webhook: warning: skipping malformed header {h!r} (expected 'Key: Value')", file=sys.stderr)
            continue
        k, _, v = h.partition(":")
        k, v = k.strip(), v.strip()
        if not k:
            print("webhook: warning: skipping header with empty name", file=sys.stderr)
            continue
        req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except Exception as e:
        print(f"webhook: error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
