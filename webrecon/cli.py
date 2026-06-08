"""Command line interface for WEBRECON.

Usage:
    webrecon scan <response-file> [--format table|json] [--target URL]
    webrecon scan -            (read raw HTTP response from stdin)
    webrecon --version

The `scan` subcommand reads an already-captured raw HTTP response (status line
+ headers + blank line + body) and reports the detected stack. WEBRECON never
touches the network; you collect the response with your own authorized tooling
(curl -i, an intercept proxy export, etc.) and feed it in.

Exit codes:
    0  ran successfully, no technologies identified
    1  ran successfully, one or more findings (treat as actionable)
    2  usage / input error
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import ReconResult, fingerprint_response, result_to_json


def _render_table(result: ReconResult) -> str:
    lines: List[str] = []
    head = f"{TOOL_NAME} {TOOL_VERSION}"
    if result.target:
        head += f"  target={result.target}"
    if result.status is not None:
        head += f"  status={result.status}"
    lines.append(head)
    lines.append("-" * max(len(head), 40))

    if not result.findings:
        lines.append("(no known technologies matched)")
        return "\n".join(lines)

    cat_w = max(len(f.category) for f in result.findings)
    name_w = max(len(f.name) for f in result.findings)
    cat_w = max(cat_w, len("CATEGORY"))
    name_w = max(name_w, len("TECHNOLOGY"))
    lines.append(f"{'CATEGORY':<{cat_w}}  {'TECHNOLOGY':<{name_w}}  {'VER':<10}  CONF")
    for f in result.findings:
        ver = f.version or "-"
        lines.append(
            f"{f.category:<{cat_w}}  {f.name:<{name_w}}  {ver:<10}  {f.confidence}%"
        )
    lines.append("")
    lines.append("evidence:")
    for f in result.findings:
        for ev in f.evidence:
            lines.append(f"  [{f.name}] {ev}")
    return "\n".join(lines)


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Defensive web technology fingerprinting from a captured HTTP response (offline, read-only).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan",
        help="fingerprint a captured raw HTTP response file (or - for stdin)",
    )
    scan.add_argument(
        "response",
        help="path to a file containing a raw HTTP response, or - for stdin",
    )
    scan.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )
    scan.add_argument(
        "--target",
        default=None,
        help="optional label/URL to record in the report",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    try:
        text = _read_input(args.response)
    except OSError as exc:
        print(f"{TOOL_NAME}: cannot read {args.response!r}: {exc}", file=sys.stderr)
        return 2

    if not text.strip():
        print(f"{TOOL_NAME}: empty input", file=sys.stderr)
        return 2

    result = fingerprint_response(text, target=args.target)

    if args.format == "json":
        print(result_to_json(result))
    else:
        print(_render_table(result))

    # Non-zero exit when there are findings (actionable), zero when clean.
    return 1 if result.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
