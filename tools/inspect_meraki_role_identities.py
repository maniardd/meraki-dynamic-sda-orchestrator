#!/usr/bin/env python3
"""Report Meraki workflow role-identity readiness without exposing tokens."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from orchestrator.auth import load_hashed_token_identities


EXPECTED_ACTORS = (
    "meraki-planner",
    "meraki-approver",
    "meraki-operator",
    "meraki-auditor",
)


def inspect_identities(identity_file: Path) -> dict[str, object]:
    """Return a structural-only Meraki identity readiness report."""

    identity_path = identity_file.expanduser().resolve()
    identities = load_hashed_token_identities(str(identity_path))
    actors = {str(principal["actor"]) for principal in identities.values()}
    present = [actor for actor in EXPECTED_ACTORS if actor in actors]
    missing = [actor for actor in EXPECTED_ACTORS if actor not in actors]
    mode = stat.S_IMODE(os.stat(identity_path).st_mode)

    return {
        "schema_version": "1.0",
        "inspection_mode": "read_only",
        "identity_count": len(identities),
        "meraki_role_actors_present": present,
        "missing_meraki_role_actors": missing,
        "non_meraki_identity_count": len(actors - set(EXPECTED_ACTORS)),
        "identity_file_mode": format(mode, "04o"),
        "private_file_mode": mode == 0o600,
        "ready_for_meraki_targets": not missing and mode == 0o600,
        "contains_secret_values": False,
        "contains_token_digests": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity-file", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        report = inspect_identities(arguments.identity_file)
    except (OSError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "inspection_mode": "read_only",
                    "safe": False,
                    "error_type": type(exc).__name__,
                    "contains_secret_values": False,
                    "contains_token_digests": False,
                },
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
