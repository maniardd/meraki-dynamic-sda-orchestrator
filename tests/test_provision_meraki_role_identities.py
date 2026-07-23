from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from admin.provision_meraki_role_identities import provision_identities
from orchestrator.auth import load_hashed_token_identities


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class ProvisionMerakiRoleIdentitiesTests(unittest.TestCase):
    def identity_file(self, directory: str, identities: dict) -> Path:
        path = Path(directory) / "token-identities.json"
        path.write_text(
            json.dumps({"version": 1, "identities": identities}),
            encoding="utf-8",
        )
        os.chmod(path, 0o600)
        return path

    def test_provisions_roles_and_preserves_unmanaged_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            planner_digest = digest("planner-token-value-with-required-length")
            path = self.identity_file(
                directory,
                {
                    planner_digest: {
                        "actor": "meraki-planner",
                        "roles": ["planner"],
                    }
                },
            )

            provision_identities(
                path,
                {
                    "approver": digest("approver-token-value-with-required-length"),
                    "operator": digest("operator-token-value-with-required-length"),
                    "auditor": digest("auditor-token-value-with-required-length"),
                },
            )

            identities = load_hashed_token_identities(str(path))
            self.assertEqual(4, len(identities))
            self.assertEqual("meraki-planner", identities[planner_digest]["actor"])
            if os.name != "nt":
                self.assertEqual(0o600, path.stat().st_mode & 0o777)
            actors = {principal["actor"] for principal in identities.values()}
            self.assertEqual(
                {
                    "meraki-planner",
                    "meraki-approver",
                    "meraki-operator",
                    "meraki-auditor",
                },
                actors,
            )

    def test_rotation_replaces_prior_managed_actors(self):
        with tempfile.TemporaryDirectory() as directory:
            old_approver = digest("old-approver-token-value-with-required-length")
            path = self.identity_file(
                directory,
                {
                    old_approver: {
                        "actor": "meraki-approver",
                        "roles": ["approver"],
                    }
                },
            )

            provision_identities(
                path,
                {
                    "approver": digest("new-approver-token-value-with-required-length"),
                    "operator": digest("new-operator-token-value-with-required-length"),
                    "auditor": digest("new-auditor-token-value-with-required-length"),
                },
            )

            identities = load_hashed_token_identities(str(path))
            self.assertNotIn(old_approver, identities)
            self.assertEqual(3, len(identities))

    def test_invalid_or_duplicate_digests_fail_before_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.identity_file(
                directory,
                {
                    digest("planner-token-value-with-required-length"): {
                        "actor": "meraki-planner",
                        "roles": ["planner"],
                    }
                },
            )
            before = path.read_bytes()
            valid = digest("valid-role-token-value-with-required-length")

            with self.assertRaisesRegex(ValueError, "lowercase SHA-256"):
                provision_identities(
                    path,
                    {
                        "approver": "not-a-digest",
                        "operator": digest("operator-token-value-with-required-length"),
                        "auditor": digest("auditor-token-value-with-required-length"),
                    },
                )
            self.assertEqual(before, path.read_bytes())

            with self.assertRaisesRegex(ValueError, "unique token digest"):
                provision_identities(
                    path,
                    {
                        "approver": valid,
                        "operator": valid,
                        "auditor": digest("auditor-token-value-with-required-length"),
                    },
                )
            self.assertEqual(before, path.read_bytes())


if __name__ == "__main__":
    unittest.main()
