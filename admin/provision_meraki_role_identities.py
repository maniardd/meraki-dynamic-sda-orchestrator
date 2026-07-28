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

from orchestrator.auth import (
    AuthenticationConfigError,
    TOKEN_DIGEST,
    load_hashed_token_identities,
)


ROLE_ACTORS = {
    "planner": "meraki-planner",
    "approver": "meraki-approver",
    "operator": "meraki-operator",
    "auditor": "meraki-auditor",
}

# The existing administrative workflow deliberately preserves the planner
# identity.  A separately reviewed bootstrap path may rotate all four roles.
DEFAULT_MANAGED_ROLES = frozenset({"approver", "operator", "auditor"})


def _fsync_directory(directory: Path) -> None:
    if not hasattr(os, "O_DIRECTORY"):
        return
    descriptor = os.open(str(directory), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def provision_identities(
    output: Path,
    digests: Mapping[str, str],
    *,
    managed_roles: frozenset[str] = DEFAULT_MANAGED_ROLES,
) -> Dict[str, Dict[str, object]]:
    """Atomically replace the managed role identities while preserving others."""

    normalized = {str(role): str(digest).lower() for role, digest in digests.items()}
    if not managed_roles or not managed_roles.issubset(ROLE_ACTORS):
        raise ValueError("managed roles are invalid")
    if set(normalized) != set(managed_roles):
        raise ValueError("digests must exactly match the managed roles")
    if any(not TOKEN_DIGEST.fullmatch(digest) for digest in normalized.values()):
        raise ValueError("every role identity must be a lowercase SHA-256 digest")
    if len(set(normalized.values())) != len(normalized):
        raise ValueError("each managed role must use a unique token digest")

    identity_path = output.expanduser().resolve()
    identities = load_hashed_token_identities(str(identity_path))
    managed_actors = {ROLE_ACTORS[role] for role in managed_roles}
    retained = {
        digest: dict(principal)
        for digest, principal in identities.items()
        if str(principal["actor"]) not in managed_actors
    }
    for role in sorted(managed_roles):
        actor = ROLE_ACTORS[role]
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
        _fsync_directory(identity_path.parent)
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


def restore_identities(output: Path, backup: Path) -> None:
    """Atomically restore a validated, hash-only identity-file backup."""

    identity_path = output.expanduser().resolve()
    backup_path = backup.expanduser().resolve()
    if identity_path == backup_path:
        raise ValueError("identity file and backup file must differ")
    if backup_path.is_symlink():
        raise ValueError("identity backup must not be a symlink")
    try:
        load_hashed_token_identities(str(backup_path))
    except AuthenticationConfigError as exc:
        raise ValueError("identity backup is invalid") from exc
    os.replace(str(backup_path), str(identity_path))
    os.chmod(str(identity_path), 0o600)
    _fsync_directory(identity_path.parent)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--restore-from", type=Path)
    for role in ROLE_ACTORS:
        parser.add_argument(f"--{role}-digest")
    arguments = parser.parse_args()
    try:
        digests = {
            role: getattr(arguments, f"{role}_digest") for role in ROLE_ACTORS
        }
        if arguments.restore_from is not None:
            if any(value is not None for value in digests.values()):
                raise ValueError("restore must not include role digests")
            restore_identities(arguments.output, arguments.restore_from)
            print("restored_role_identities=true")
            return 0
        if any(value is None for value in digests.values()):
            raise ValueError("every role digest is required")
        identities = provision_identities(arguments.output, digests)
    except ValueError as exc:
        parser.error(str(exc))
    print("provisioned_role_identities=3")
    print(f"total_identities={len(identities)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
