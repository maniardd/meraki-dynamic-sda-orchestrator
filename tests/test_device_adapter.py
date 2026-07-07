from __future__ import annotations

import unittest

from orchestrator.adapters import (
    AdapterError,
    ConfigurationRejectedError,
    IosXeSshAdapter,
)


class FakeConnection:
    def __init__(self):
        self.config_output = "configuration accepted"
        self.diff_output = "!Contextual Config Diffs:\n!No changes were found"
        self.commands = []
        self.disconnected = False

    def send_command(self, command, **_kwargs):
        self.commands.append(command)
        if command.startswith("dir flash:"):
            return "123 -rw- 99 sda-run_123.cfg"
        if command.startswith("show archive config differences"):
            return self.diff_output
        return "show output"

    def send_command_timing(self, command, **_kwargs):
        if command.startswith("copy running-config"):
            return "Destination filename [sda-run_123.cfg]?"
        return "completed"

    def send_config_set(self, _commands, **_kwargs):
        return self.config_output

    def disconnect(self):
        self.disconnected = True


class DeviceAdapterTests(unittest.TestCase):
    def setUp(self):
        self.connection = FakeConnection()
        self.device = {
            "management_ip": "192.0.2.10",
            "credential_ref": "secret://lab/device",
        }
        self.adapter = IosXeSshAdapter(
            self.device,
            lambda _ref: {"username": "user", "password": "password"},
            connect_factory=lambda **_kwargs: self.connection,
        )
        self.adapter.connect()

    def test_show_commands_are_bounded(self):
        result = self.adapter.run_show("show version")
        self.assertEqual("show version", result["command"])
        with self.assertRaises(ConfigurationRejectedError):
            self.adapter.run_show("configure terminal")
        with self.assertRaises(ConfigurationRejectedError):
            self.adapter.run_show("show version\nreload")

    def test_checkpoint_is_created_and_verified(self):
        result = self.adapter.create_checkpoint("run_123")
        self.assertTrue(result["verified"])
        self.assertEqual("flash:sda-run_123.cfg", result["checkpoint"])

    def test_unresolved_secret_is_rejected(self):
        with self.assertRaises(ConfigurationRejectedError):
            self.adapter.apply_block(["authentication-key <secret:secret://lab/lisp>"])

    def test_cli_error_fails_the_block(self):
        self.connection.config_output = "% Invalid input detected"
        with self.assertRaises(AdapterError):
            self.adapter.apply_block(["router lisp"])

    def test_checkpoint_path_is_constrained(self):
        with self.assertRaises(ConfigurationRejectedError):
            self.adapter.rollback("flash:other.cfg")

    def test_rollback_is_verified_against_checkpoint(self):
        result = self.adapter.rollback("flash:sda-run_123.cfg")
        self.assertTrue(result["verified"])
        self.assertIn("verification_output_hash", result)
        self.assertIn(
            "show archive config differences flash:sda-run_123.cfg system:running-config",
            self.connection.commands,
        )

    def test_rollback_with_remaining_diff_is_rejected(self):
        self.connection.diff_output = "!Contextual Config Diffs:\n+router lisp"
        with self.assertRaisesRegex(AdapterError, "configuration differences"):
            self.adapter.rollback("flash:sda-run_123.cfg")


if __name__ == "__main__":
    unittest.main()
