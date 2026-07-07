from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from orchestrator.auth import (
    AuthenticationConfigError,
    load_hashed_token_identities,
    match_hashed_principal,
    token_sha256,
)


class HashedTokenAuthenticationTests(unittest.TestCase):
    def identity_file(self, directory, document):
        path = Path(directory) / "token-identities.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        os.chmod(str(path), 0o600)
        return path

    def test_private_file_authenticates_without_storing_bearer_value(self):
        token = "phase3-validation-token-value-0001"
        digest = token_sha256(token)
        with tempfile.TemporaryDirectory() as directory:
            path = self.identity_file(
                directory,
                {
                    "version": 1,
                    "identities": {
                        digest: {"actor": "meraki-planner", "roles": ["viewer", "planner"]}
                    },
                },
            )
            identities = load_hashed_token_identities(str(path))
            principal = match_hashed_principal(token, identities)
            self.assertEqual("meraki-planner", principal["actor"])
            self.assertEqual({"viewer", "planner"}, principal["roles"])
            self.assertNotIn(token, path.read_text(encoding="utf-8"))

    def test_short_or_wrong_token_does_not_match(self):
        identities = {
            token_sha256("phase3-validation-token-value-0001"): {
                "actor": "auditor",
                "roles": ["auditor"],
            }
        }
        self.assertIsNone(match_hashed_principal("short", identities))
        self.assertIsNone(
            match_hashed_principal("phase3-validation-token-value-9999", identities)
        )

    def test_invalid_digest_or_role_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.identity_file(
                directory,
                {
                    "version": 1,
                    "identities": {
                        "not-a-digest": {"actor": "planner", "roles": ["superuser"]}
                    },
                },
            )
            with self.assertRaises(AuthenticationConfigError):
                load_hashed_token_identities(str(path))

    def test_group_readable_identity_file_is_rejected(self):
        if os.name == "nt":
            self.skipTest("Windows does not enforce POSIX group permission bits")
        with tempfile.TemporaryDirectory() as directory:
            path = self.identity_file(
                directory,
                {
                    "version": 1,
                    "identities": {
                        token_sha256("phase3-validation-token-value-0001"): {
                            "actor": "auditor",
                            "roles": ["auditor"],
                        }
                    },
                },
            )
            os.chmod(str(path), 0o640)
            with self.assertRaisesRegex(AuthenticationConfigError, "group or other"):
                load_hashed_token_identities(str(path))


if __name__ == "__main__":
    unittest.main()
