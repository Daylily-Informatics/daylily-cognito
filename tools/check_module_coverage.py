#!/usr/bin/env python3
"""Fail if any package module falls below a required coverage floor."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("coverage_json", nargs="?", default="coverage.json", help="Path to coverage.py JSON report")
    parser.add_argument(
        "--threshold",
        type=float,
        default=60.0,
        help="Minimum allowed per-module coverage percentage",
    )
    parser.add_argument(
        "--package-prefix",
        default="daylily_auth_cognito/",
        help="Package path prefix to check inside the coverage report",
    )
    return parser.parse_args()


def _percent_covered(summary: dict[str, object]) -> float:
    percent = summary.get("percent_covered")
    if isinstance(percent, (int, float)):
        return float(percent)

    covered = int(summary.get("covered_lines", 0))
    statements = int(summary.get("num_statements", 0))
    if statements == 0:
        return 100.0
    return covered * 100.0 / statements


def main() -> int:
    args = _parse_args()
    coverage_path = Path(args.coverage_json)
    payload = json.loads(coverage_path.read_text(encoding="utf-8"))
    files = payload.get("files", {})

    checked: list[tuple[str, float]] = []
    failures: list[tuple[str, float]] = []

    for raw_path, info in sorted(files.items()):
        path = str(raw_path).replace("\\", "/")
        if not path.startswith(args.package_prefix) or not path.endswith(".py"):
            continue

        summary = info.get("summary", {})
        if not isinstance(summary, dict):
            continue

        percent = _percent_covered(summary)
        checked.append((path, percent))
        if percent < args.threshold:
            failures.append((path, percent))

    if not checked:
        print(f"No modules found under {args.package_prefix!r} in {coverage_path}", file=sys.stderr)
        return 1

    if failures:
        print(
            f"Per-module coverage check failed for {len(failures)} module(s) below {args.threshold:.0f}%:",
            file=sys.stderr,
        )
        for path, percent in failures:
            print(f"  {path}: {percent:.1f}%", file=sys.stderr)
        return 1

    print(
        f"Per-module coverage check passed: {len(checked)} module(s) under "
        f"{args.package_prefix} are >= {args.threshold:.0f}%",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
