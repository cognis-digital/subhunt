"""Command-line interface for SUBHUNT."""
from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import aggregate


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Aggregate & dedupe subdomain enumeration output from multiple "
            "sources into one clean set (defensive / authorized testing)."
        ),
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    merge = sub.add_parser(
        "merge",
        help="Merge subdomain source files/dirs into one deduped set.",
    )
    merge.add_argument(
        "sources", nargs="+",
        help="Source files or directories (one host per line; "
             "comments with '#'; first CSV/whitespace field is the host).",
    )
    merge.add_argument(
        "-s", "--scope", default="",
        help="Restrict to this registrable domain (e.g. example.com).",
    )
    merge.add_argument(
        "-f", "--format", choices=("table", "json"), default="table",
        help="Output format (default: table).",
    )
    return parser


def _render_table(result) -> str:
    lines = []
    st = result.to_dict()["stats"]
    lines.append(f"# SUBHUNT scope={result.scope or '*'}")
    lines.append(
        "# lines={total_lines} unique={unique} dup={duplicates} "
        "invalid={invalid} oos={out_of_scope}".format(**st)
    )
    lines.append(f"# sources: {', '.join(result.source_files)}")
    for s in result.subdomains:
        srcs = ",".join(sorted(s.sources))
        lines.append(f"{s.host}\t[{s.source_count}]\t{srcs}")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "merge":
        try:
            result = aggregate(args.sources, scope=args.scope)
        except (OSError, ValueError) as exc:
            print(f"{TOOL_NAME}: error: {exc}", file=sys.stderr)
            return 2

        if args.format == "json":
            print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        else:
            print(_render_table(result))

        # Non-zero exit when findings exist (so it composes in pipelines
        # the same way grep/amass do), or when nothing usable was parsed.
        if result.unique_count > 0:
            return 1
        return 0

    parser.error("unknown command")
    return 2  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
