#!/usr/bin/env python3
"""Provision Meraki workflow API roles from SHA-256 token digests only."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Dict, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from orchestrator.auth import TOKEN_DIGEST, load_hashed_token_identities


ROLE_ACTORS = {
    "approver": "meraki-approver",
    "operator": "meraki-operator",
    "auditor": "meraki-auditor",
}


def provision_identities(
    output: Path,
    digests: Mapping[str, str],
) -> Dict[str, Dict[str, object]]:
    """Atomically replace the managed role identities while preserving others."""

    normalized = {str(role): str(digest).lower() for role, digest in digests.items()}
    if set(normalized) != set(ROLE_ACTORS):
        raise ValueError("exactly approver, operator, and auditor digests are required")
    if any(not TOKEN_DIGEST.fullmatch(digest) for digest in normalized.values()):
        raise ValueError("every role identity must be a lowercase SHA-256 digest")
    if len(set(normalized.values())) != len(normalized):
        raise ValueError("each managed role must use a unique token digest")

    identity_path = output.expanduser().resolve()
    identities = load_hashed_token_identities(str(identity_path))
    managed_actors = set(ROLE_ACTORS.values())
    retained = {
        digest: dict(principal)
        for digest, principal in identities.items()
        if str(principal["actor"]) not in managed_actors
    }
    for role, actor in ROLE_ACTORS.items():
        digest = normalized[role]
        if digest in retained:
            raise ValueError("managed digest collides with an existing identity")
        retained[digest] = {"actor": actor, "roles": [role]}
    if len(retained) > 32:
        raise ValueError("token identity limit reached")

    document = {"version": 1, "identities": retained}
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".token-identities-",
        dir=str(identity_path.parent),
        text=True,
    )
    try:
        os.chmod(temporary_name, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, str(identity_path))
        os.chmod(str(identity_path), 0o600)
        if hasattr(os, "O_DIRECTORY"):
            directory = os.open(str(identity_path.parent), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise
    return retained


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    for role in ROLE_ACTORS:
        parser.add_argument(f"--{role}-digest", required=True)
    arguments = parser.parse_args()
    try:
        identities = provision_identities(
            arguments.output,
            {
                role: getattr(arguments, f"{role}_digest")
                for role in ROLE_ACTORS
            },
        )
    except ValueError as exc:
        parser.error(str(exc))
    print("provisioned_role_identities=3")
    print(f"total_identities={len(identities)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
