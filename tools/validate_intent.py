#!/usr/bin/env python3
"""Validate a production fabric-intent document without touching devices."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from orchestrator.intent import load_intent, validate_intent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("intent", help="Path to YAML fabric intent")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument(
        "--warnings-as-errors",
        action="store_true",
        help="Return non-zero when warnings are present",
    )
    args = parser.parse_args()

    try:
        document = load_intent(args.intent)
    except Exception as exc:
        if args.json:
            print(json.dumps({"valid": False, "load_error": str(exc)}, indent=2))
        else:
            print(f"LOAD ERROR: {exc}", file=sys.stderr)
        return 2

    result = validate_intent(document)
    if args.json:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        status = "VALID" if result.is_valid else "INVALID"
        print(
            f"{status}: {args.intent} "
            f"({len(result.errors)} errors, {len(result.warnings)} warnings)"
        )
        for issue in result.issues:
            print(
                f"{issue.severity.upper():7} {issue.code:30} "
                f"{issue.path}: {issue.message}"
            )

    if not result.is_valid:
        return 1
    if args.warnings_as_errors and result.warnings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
