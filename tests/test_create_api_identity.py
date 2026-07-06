from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from orchestrator.auth import load_hashed_token_identities, match_hashed_principal
from tools.create_api_identity import create_identity


class CreateApiIdentityTests(unittest.TestCase):
    def test_generated_value_is_returned_once_and_only_digest_is_stored(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "private" / "token-identities.json"
            token = create_identity(output, "meraki-planner", ["viewer", "planner"])
            self.assertGreaterEqual(len(token), 32)
            self.assertNotIn(token, output.read_text(encoding="utf-8"))
            principal = match_hashed_principal(
                token, load_hashed_token_identities(str(output))
            )
            self.assertEqual("meraki-planner", principal["actor"])

    def test_additional_identity_preserves_existing_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "token-identities.json"
            planner = create_identity(output, "planner", ["planner"])
            auditor = create_identity(output, "auditor", ["auditor"])
            identities = load_hashed_token_identities(str(output))
            self.assertEqual(2, len(identities))
            self.assertEqual("planner", match_hashed_principal(planner, identities)["actor"])
            self.assertEqual("auditor", match_hashed_principal(auditor, identities)["actor"])

    def test_unsupported_role_is_rejected_before_file_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "token-identities.json"
            with self.assertRaisesRegex(ValueError, "approved API roles"):
                create_identity(output, "invalid", ["superuser"])
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
