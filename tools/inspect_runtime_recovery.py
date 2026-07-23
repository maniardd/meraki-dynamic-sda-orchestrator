#!/usr/bin/env python3
"""Inspect recovery locks and run state without changing PostgreSQL."""

from __future__ import annotations

import json
import os
import sys

from orchestrator.runtime_recovery import (
    RuntimeRecoveryInspectionError,
    inspect_postgresql,
)


def main() -> int:
    database_url = os.environ.get(
        "ORCHESTRATOR_DATABASE_URL",
        "postgresql:///sda_orchestrator?host=/var/run/postgresql",
    )
    try:
        report = inspect_postgresql(database_url)
    except RuntimeRecoveryInspectionError as exc:
        print(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "inspection_mode": "read_only",
                    "safe": False,
                    "error_type": type(exc).__name__,
                    "contains_secret_values": False,
                },
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["safe"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
