"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Sequence

from . import __version__
from .check import ERROR, Result, exit_code, run_checks, summarise
from .sources import expand_pem_paths, parse_target, read_hosts_file


def render_text(results: list[Result], warn_days: int) -> str:
    headers = ["STATUS", "DAYS", "EXPIRES (UTC)", "SUBJECT", "ISSUER", "SOURCE"]
    rows = []
    for r in results:
        if r.status == ERROR:
            rows.append(["ERROR", "-", "-", "-", "-", f"{r.source}  ({r.error})"])
        else:
            expires = r.not_after[:16].replace("T", " ")
            rows.append(
                [r.status.upper(), str(r.days_remaining), expires, r.subject, r.issuer, r.source]
            )
    widths = [max(len(row[i]) for row in [headers] + rows) for i in range(len(headers))]
    lines = []
    for row in [headers] + rows:
        cells = [row[0].ljust(widths[0]), row[1].rjust(widths[1])]
        cells += [row[i].ljust(widths[i]) for i in range(2, 5)]
        cells.append(row[5])
        lines.append("  ".join(cells).rstrip())
    counts = summarise(results)
    lines.append("")
    lines.append(
        f"{len(results)} checked: {counts['ok']} ok, {counts['expiring']} expiring within "
        f"{warn_days} days, {counts['expired']} expired, {counts['error']} could not be checked"
    )
    return "\n".join(lines)


def render_json(results: list[Result], warn_days: int, now: datetime) -> str:
    return json.dumps(
        {
            "checked_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "warn_days": warn_days,
            "summary": summarise(results),
            "results": [r.to_dict() for r in results],
        },
        indent=2,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cert-expiry-watch",
        description="Report TLS certificate expiry for live hosts and PEM files. "
        "Exits 1 if any certificate is expired or inside the warning window.",
    )
    parser.add_argument("targets", nargs="*", metavar="HOST[:PORT]", help="hosts to connect to (port defaults to 443)")
    parser.add_argument("--hosts", metavar="FILE", action="append", default=[], help="file with one HOST[:PORT] per line; repeatable")
    parser.add_argument("--pem", metavar="PATH", action="append", default=[], help="PEM certificate file, or a directory of .pem/.crt/.cer files; repeatable")
    parser.add_argument("--warn-days", type=int, default=21, help="warn when fewer than this many days remain (default 21)")
    parser.add_argument("--timeout", type=float, default=5.0, help="seconds to wait for each host (default 5)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of a table")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None, stdout=None, now: datetime | None = None) -> int:
    stdout = stdout if stdout is not None else sys.stdout
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.warn_days < 0:
        parser.error("--warn-days must not be negative")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    try:
        targets = [parse_target(t) for t in args.targets]
        for hosts_file in args.hosts:
            targets.extend(read_hosts_file(hosts_file))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    files = expand_pem_paths(args.pem)

    if not targets and not files:
        parser.error("nothing to check: give hosts, --hosts FILE or --pem PATH")

    now = now or datetime.now(timezone.utc)
    results = run_checks(targets, files, args.warn_days, args.timeout, now)
    if args.json:
        print(render_json(results, args.warn_days, now), file=stdout)
    else:
        print(render_text(results, args.warn_days), file=stdout)
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
