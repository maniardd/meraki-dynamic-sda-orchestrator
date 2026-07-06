#!/usr/bin/env python3
"""Audit an exported Cisco Workflow for production safety controls."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from orchestrator.workflow_audit import audit_workflow_export


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workflow_export")
    args = parser.parse_args()
    document = json.loads(Path(args.workflow_export).read_text(encoding="utf-8-sig"))
    result = audit_workflow_export(document)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["production_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
