#!/usr/bin/env python3
"""Create fresh, one-time Meraki Account Key values without logging them.

The generated values are written only to an operator-owned mode-0600 file on
the Ubuntu relay.  The API identity store receives SHA-256 digests, never the
plaintext values.  The caller must delete the one-time file after entering the
values in the four Meraki Account Keys.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from admin.provision_meraki_role_identities import ROLE_ACTORS, provision_identities
from orchestrator.auth import token_sha256


ONE_TIME_FILE_VERSION = 1


def _require_private_directory(path: Path) -> None:
    details = path.stat()
    if not stat.S_ISDIR(details.st_mode):
        raise ValueError("one-time account-key parent must be a directory")
    if os.name != "nt" and details.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("one-time account-key parent must not be group or world writable")


def _create_private_file(path: Path, document: Mapping[str, object]) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("one-time account-key file already exists")
    _require_private_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(path), flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            if hasattr(os, "fchmod"):
                os.fchmod(handle.fileno(), 0o600)
            json.dump(document, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise ValueError("one-time account-key file mode is not private")
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def generate_and_provision(identity_file: Path, one_time_file: Path) -> dict[str, object]:
    """Generate four unique values, persist their hashes, and retain values once."""

    identity_path = identity_file.expanduser().resolve()
    requested_output = one_time_file.expanduser()
    if requested_output.is_symlink():
        raise ValueError("one-time account-key file must not be a symlink")
    output_path = requested_output.resolve()
    if identity_path == output_path:
        raise ValueError("identity file and one-time account-key file must differ")

    tokens = {role: secrets.token_urlsafe(48) for role in sorted(ROLE_ACTORS)}
    digests = {role: token_sha256(value) for role, value in tokens.items()}
    if not all(digests.values()) or len(set(tokens.values())) != len(tokens):
        raise ValueError("generated account-key values are invalid")

    # Refuse to rotate the identity store unless the one-time file can first
    # be created safely.  The file contains the only recoverable copies.
    one_time_document = {
        "version": ONE_TIME_FILE_VERSION,
        "purpose": "meraki_account_key_one_time_bootstrap",
        "account_keys": tokens,
    }
    _create_private_file(output_path, one_time_document)
    try:
        provision_identities(
            identity_path,
            digests,
            managed_roles=frozenset(ROLE_ACTORS),
        )
    except Exception:
        try:
            output_path.unlink()
        except OSError:
            pass
        raise

    return {
        "generated_role_count": len(tokens),
        "one_time_account_key_file": str(output_path),
        "contains_secret_values": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity-file", required=True, type=Path)
    parser.add_argument("--one-time-file", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        report = generate_and_provision(arguments.identity_file, arguments.one_time_file)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print("generated_role_count={generated_role_count}".format(**report))
    print("one_time_account_key_file={one_time_account_key_file}".format(**report))
    print("contains_secret_values=false")
    print("next_action=enter_each_value_once_in_matching_meraki_account_key_then_delete_file")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
