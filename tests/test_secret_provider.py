from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from orchestrator.secrets import (
    SecretProviderError,
    StrictJsonFileSecretProvider,
    VaultKvSecretProvider,
    build_secret_provider,
)


class FakeResponse:
    status_code = 200

    def json(self):
        return {"data": {"data": {"username": "network-user", "password": "private"}}}


class SecretProviderTests(unittest.TestCase):
    def private_file(self, directory, name, value):
        path = Path(directory) / name
        path.write_text(value, encoding="utf-8")
        os.chmod(str(path), 0o600)
        return path

    def test_strict_file_resolves_values_and_credentials_without_inline_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.private_file(
                directory,
                "secrets.json",
                json.dumps(
                    {
                        "lab/lisp": {"value": "lisp-private-value"},
                        "lab/device": {
                            "username": "network-user",
                            "password": "network-private-value",
                            "enable_secret": "enable-private-value",
                        },
                    }
                ),
            )
            provider = StrictJsonFileSecretProvider(str(path))
            self.assertEqual("lisp-private-value", provider.resolve_value("secret://lab/lisp"))
            credentials = provider.resolve_credentials("secret://lab/device")
            self.assertEqual("network-user", credentials["username"])
            self.assertEqual("network-private-value", credentials["password"])

    def test_secret_file_with_group_or_other_access_is_rejected(self):
        if os.name == "nt":
            self.skipTest("Windows does not enforce POSIX group permission bits")
        with tempfile.TemporaryDirectory() as directory:
            path = self.private_file(directory, "secrets.json", "{}")
            os.chmod(str(path), 0o640)
            with self.assertRaisesRegex(SecretProviderError, "group or other"):
                StrictJsonFileSecretProvider(str(path))

    def test_unknown_or_malformed_reference_fails_without_echoing_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.private_file(directory, "secrets.json", "{}")
            provider = StrictJsonFileSecretProvider(str(path))
            private_reference = "secret://missing/private-name"
            with self.assertRaises(SecretProviderError) as raised:
                provider.resolve(private_reference)
            self.assertNotIn(private_reference, str(raised.exception))

    @mock.patch("orchestrator.secrets.requests.get", return_value=FakeResponse())
    def test_vault_uses_https_tls_verification_timeout_and_token_header(self, request_get):
        with tempfile.TemporaryDirectory() as directory:
            token = self.private_file(directory, "vault-token", "vault-private-token")
            provider = VaultKvSecretProvider("https://vault.example.invalid", str(token))
            credentials = provider.resolve_credentials("secret://campus/data/device-01")
            self.assertEqual("network-user", credentials["username"])
            args, kwargs = request_get.call_args
            self.assertEqual(True, kwargs["verify"])
            self.assertEqual(10, kwargs["timeout"])
            self.assertEqual("vault-private-token", kwargs["headers"]["X-Vault-Token"])
            self.assertNotIn("vault-private-token", args[0])

    def test_provider_factory_fails_closed(self):
        with self.assertRaisesRegex(SecretProviderError, "supported"):
            build_secret_provider({})


if __name__ == "__main__":
    unittest.main()
