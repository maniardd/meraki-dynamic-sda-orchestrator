#!/usr/bin/env python3
"""Validate or compile the portable Meraki workflow build specification."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from orchestrator.meraki_workflow_package import (
    compile_workflow_build_plan,
    load_workflow_package,
    validate_workflow_package,
    workflow_operation_matrix,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "manifest",
        nargs="?",
        type=Path,
        default=Path("workflows/production_workflow_manifest.yaml"),
    )
    parser.add_argument("--compile", action="store_true", dest="compile_plan")
    parser.add_argument("--matrix", action="store_true")
    args = parser.parse_args()
    document = load_workflow_package(args.manifest)
    validation = validate_workflow_package(document)
    payload: Dict[str, Any] = {"validation": validation}
    if validation["safe_to_build"] and args.compile_plan:
        payload["build_plan"] = compile_workflow_build_plan(document)
    if validation["safe_to_build"] and args.matrix:
        payload["operation_matrix"] = workflow_operation_matrix(document)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if validation["safe_to_build"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
