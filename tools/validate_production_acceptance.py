#!/usr/bin/env python3
"""Validate the production acceptance registry without exposing evidence values."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from orchestrator.acceptance import (
    load_acceptance_registry,
    load_workflow_manifest,
    validate_production_acceptance,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "registry",
        nargs="?",
        type=Path,
        default=Path("acceptance/production-acceptance.sjc23.yaml"),
    )
    parser.add_argument(
        "--workflow-manifest",
        type=Path,
        default=Path("workflows/production_workflow_manifest.yaml"),
    )
    parser.add_argument(
        "--require-ready",
        action="store_true",
        help="Return exit code 2 unless controlled Apply enablement is fully approved",
    )
    args = parser.parse_args()

    registry = load_acceptance_registry(args.registry)
    workflow_manifest = load_workflow_manifest(args.workflow_manifest)
    result = validate_production_acceptance(
        registry,
        workflow_manifest=workflow_manifest,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["registry_valid"]:
        return 1
    if args.require_ready and not result["ready_for_controlled_enablement"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
