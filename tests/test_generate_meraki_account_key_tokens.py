from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from admin.generate_meraki_account_key_tokens import generate_and_provision
from orchestrator.auth import load_hashed_token_identities, token_sha256


class GenerateMerakiAccountKeyTokensTests(unittest.TestCase):
    def identity_file(self, directory: str) -> Path:
        path = Path(directory) / "token-identities.json"
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "identities": {
                        token_sha256("old-planner-token-with-required-length-12345"): {
                            "actor": "meraki-planner",
                            "roles": ["viewer", "planner"],
                        },
                        token_sha256("old-operator-token-with-required-length-12345"): {
                            "actor": "meraki-operator",
                            "roles": ["operator"],
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        os.chmod(path, 0o600)
        return path

    def test_generates_four_distinct_one_time_values_and_hashes_only_identity_store(self):
        with tempfile.TemporaryDirectory() as directory:
            identity_file = self.identity_file(directory)
            one_time_file = Path(directory) / "meraki-account-keys.once.json"

            report = generate_and_provision(identity_file, one_time_file)

            self.assertEqual(4, report["generated_role_count"])
            self.assertFalse(report["contains_secret_values"])
            self.assertEqual(str(one_time_file.resolve()), report["one_time_account_key_file"])
            values = json.loads(one_time_file.read_text(encoding="utf-8"))["account_keys"]
            self.assertEqual({"planner", "approver", "operator", "auditor"}, set(values))
            self.assertEqual(4, len(set(values.values())))
            self.assertTrue(all(len(value) >= 32 for value in values.values()))
            if os.name != "nt":
                self.assertEqual(0o600, one_time_file.stat().st_mode & 0o777)

            identities = load_hashed_token_identities(str(identity_file))
            self.assertEqual(4, len(identities))
            self.assertEqual(
                {
                    "meraki-planner",
                    "meraki-approver",
                    "meraki-operator",
                    "meraki-auditor",
                },
                {principal["actor"] for principal in identities.values()},
            )
            self.assertTrue(
                all(token_sha256(value) in identities for value in values.values())
            )
            self.assertNotIn(
                token_sha256("old-planner-token-with-required-length-12345"),
                identities,
            )
            self.assertNotIn(next(iter(values.values())), identity_file.read_text(encoding="utf-8"))

    def test_existing_one_time_file_blocks_rotation_without_identity_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            identity_file = self.identity_file(directory)
            before = identity_file.read_bytes()
            one_time_file = Path(directory) / "meraki-account-keys.once.json"
            one_time_file.write_text("already-present", encoding="utf-8")
            os.chmod(one_time_file, 0o600)

            with self.assertRaisesRegex(ValueError, "already exists"):
                generate_and_provision(identity_file, one_time_file)

            self.assertEqual(before, identity_file.read_bytes())
            self.assertEqual("already-present", one_time_file.read_text(encoding="utf-8"))

    @unittest.skipIf(os.name == "nt", "Windows symlink creation needs elevated privileges")
    def test_symlink_one_time_file_is_rejected_without_identity_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            identity_file = self.identity_file(directory)
            before = identity_file.read_bytes()
            target = Path(directory) / "symlink-target"
            one_time_file = Path(directory) / "meraki-account-keys.once.json"
            one_time_file.symlink_to(target)

            with self.assertRaisesRegex(ValueError, "must not be a symlink"):
                generate_and_provision(identity_file, one_time_file)

            self.assertEqual(before, identity_file.read_bytes())


if __name__ == "__main__":
    unittest.main()
