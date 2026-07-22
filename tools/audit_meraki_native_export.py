#!/usr/bin/env python3
"""Audit tenant-native Meraki workflow JSON without printing secret values."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Keep the documented ``python tools/...`` invocation working without asking
# operators to preconfigure PYTHONPATH.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from orchestrator.meraki_native_export import (
    audit_native_export,
    audit_native_export_set,
    load_native_export,
    verify_capture_fingerprint,
)
from orchestrator.meraki_workflow_package import load_workflow_package


REQUIRED_NATIVE_ACTIVITIES = (
    "HTTP Request",
    "Create Prompt",
    "Request Approval",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("exports", nargs="+", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument(
        "--fingerprint",
        type=Path,
        help="Verify one raw schema capture against a structural-only fingerprint",
    )
    parser.add_argument(
        "--inventory-only",
        action="store_true",
        help="Inventory one or more exports without requiring the full workflow set",
    )
    args = parser.parse_args()

    documents = [load_native_export(path) for path in args.exports]
    if args.fingerprint:
        if len(documents) != 1:
            parser.error("--fingerprint requires exactly one raw export")
        fingerprint = json.loads(args.fingerprint.read_text(encoding="utf-8"))
        if not isinstance(fingerprint, dict):
            parser.error("fingerprint must be a JSON object")
        result = verify_capture_fingerprint(documents[0], fingerprint)
        valid = result["capture_fingerprint_valid"]
    elif args.manifest and not args.inventory_only:
        manifest = load_workflow_package(args.manifest)
        expected_names = [item["name"] for item in manifest.get("workflows", [])]
        result = audit_native_export_set(
            documents,
            expected_workflow_names=expected_names,
            required_activity_names=REQUIRED_NATIVE_ACTIVITIES,
        )
        valid = result["native_export_set_valid"]
    else:
        reports = [audit_native_export(document) for document in documents]
        result = {"reports": reports}
        valid = all(report["native_export_valid"] for report in reports)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
