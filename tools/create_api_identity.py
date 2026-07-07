#!/usr/bin/env python3
"""Generate a bearer token while storing only its SHA-256 identity digest."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from orchestrator.auth import ACTOR, ALLOWED_ROLES, load_hashed_token_identities, token_sha256


def create_identity(output: Path, actor: str, roles: Iterable[str]) -> str:
    normalized_roles = sorted({str(role).strip() for role in roles if str(role).strip()})
    if not ACTOR.fullmatch(str(actor)):
        raise ValueError("actor must use the approved identifier format")
    if not normalized_roles or not set(normalized_roles).issubset(ALLOWED_ROLES):
        raise ValueError("roles must be selected from the approved API roles")

    identities = {}
    if output.exists():
        identities.update(load_hashed_token_identities(str(output)))
    if len(identities) >= 32:
        raise ValueError("token identity limit reached; retire an old identity first")

    token = secrets.token_urlsafe(32)
    identities[token_sha256(token)] = {"actor": actor, "roles": normalized_roles}
    document = {"version": 1, "identities": identities}

    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".token-identities-", dir=str(output.parent), text=True
    )
    try:
        os.chmod(temporary_name, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, str(output))
        os.chmod(str(output), 0o600)
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
    return token


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--roles", required=True, help="Comma-separated API roles")
    arguments = parser.parse_args()
    try:
        token = create_identity(
            arguments.output.expanduser().resolve(),
            arguments.actor,
            arguments.roles.split(","),
        )
    except ValueError as exc:
        parser.error(str(exc))
    # The newly generated bearer value is intentionally emitted exactly once.
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
