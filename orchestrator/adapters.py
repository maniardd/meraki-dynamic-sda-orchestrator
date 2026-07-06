"""Bounded device adapter interfaces.

Nothing in this module is invoked by the HTTP API yet. The SSH implementation
is deliberately lazy-loaded and requires explicit execution enablement by the
future worker process.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Callable, Dict, Mapping, Optional, Sequence

from .store import ExecutionDisabledError


class AdapterError(RuntimeError):
    pass


class ConfigurationRejectedError(AdapterError):
    pass


SAFE_SHOW = re.compile(r"^show [A-Za-z0-9_.:/|,() -]+$")
SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9_-]+$")
CLI_ERROR = re.compile(
    r"^%\s*(Invalid input|Incomplete command|Ambiguous command|Error|Failed)",
    flags=re.IGNORECASE | re.MULTILINE,
)


class DisabledAdapter:
    """Fail-closed default adapter used by the API process."""

    def __getattr__(self, _name):
        raise ExecutionDisabledError("No device execution adapter is enabled")


class IosXeSshAdapter:
    """Small, testable Netmiko boundary for a single IOS XE device."""

    def __init__(
        self,
        device: Mapping[str, Any],
        credential_resolver: Callable[[str], Mapping[str, str]],
        connect_factory: Optional[Callable[..., Any]] = None,
    ):
        self.device = dict(device)
        self.credential_resolver = credential_resolver
        self.connect_factory = connect_factory
        self.connection = None

    def connect(self) -> None:
        if self.connection is not None:
            return
        if self.connect_factory is None:
            try:
                from netmiko import ConnectHandler
            except ImportError as exc:
                raise AdapterError("netmiko is required in the worker runtime") from exc
            self.connect_factory = ConnectHandler
        credentials = self.credential_resolver(str(self.device["credential_ref"]))
        username = str(credentials.get("username", ""))
        password = str(credentials.get("password", ""))
        if not username or not password:
            raise AdapterError("Credential resolver did not return username and password")
        self.connection = self.connect_factory(
            device_type="cisco_ios",
            host=str(self.device["management_ip"]),
            username=username,
            password=password,
            secret=str(credentials.get("enable_secret", "")),
            conn_timeout=15,
            auth_timeout=20,
            banner_timeout=20,
            fast_cli=False,
        )
        if credentials.get("enable_secret"):
            self.connection.enable()

    def close(self) -> None:
        if self.connection is not None:
            self.connection.disconnect()
            self.connection = None

    def _require_connection(self):
        if self.connection is None:
            raise AdapterError("Device connection is not open")
        return self.connection

    def run_show(self, command: str) -> Dict[str, Any]:
        if not SAFE_SHOW.fullmatch(command) or "\n" in command or "\r" in command:
            raise ConfigurationRejectedError("Only bounded show commands are allowed")
        connection = self._require_connection()
        output = str(connection.send_command(command, read_timeout=60))
        return {
            "command": command,
            "output": output,
            "output_hash": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        }

    def create_checkpoint(self, run_id: str) -> Dict[str, Any]:
        if not SAFE_RUN_ID.fullmatch(run_id):
            raise ConfigurationRejectedError("Unsafe run ID")
        connection = self._require_connection()
        filename = "sda-{}.cfg".format(run_id[:40])
        response = str(
            connection.send_command_timing(
                "copy running-config flash:{}".format(filename),
                strip_prompt=False,
                strip_command=False,
            )
        )
        if "destination filename" in response.lower():
            response += str(connection.send_command_timing("", strip_prompt=False))
        verification = str(connection.send_command("dir flash:{}".format(filename), read_timeout=60))
        if filename.lower() not in verification.lower():
            raise AdapterError("Checkpoint file was not found after copy")
        return {
            "checkpoint": "flash:" + filename,
            "copy_output_hash": hashlib.sha256(response.encode("utf-8")).hexdigest(),
            "verified": True,
        }

    def apply_block(self, commands: Sequence[str]) -> Dict[str, Any]:
        if not commands:
            raise ConfigurationRejectedError("Configuration block is empty")
        normalized = []
        for command in commands:
            rendered = str(command)
            if "\n" in rendered or "\r" in rendered:
                raise ConfigurationRejectedError("Embedded line breaks are forbidden")
            if "<secret:" in rendered:
                raise ConfigurationRejectedError("Unresolved secret placeholder")
            normalized.append(rendered)
        connection = self._require_connection()
        output = str(
            connection.send_config_set(
                normalized,
                exit_config_mode=True,
                read_timeout=120,
                error_pattern=CLI_ERROR.pattern,
            )
        )
        if CLI_ERROR.search(output):
            raise AdapterError("IOS XE rejected one or more configuration commands")
        return {
            "command_count": len(normalized),
            "command_hash": hashlib.sha256(
                "\n".join(normalized).encode("utf-8")
            ).hexdigest(),
            "output_hash": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        }

    def rollback(self, checkpoint: str) -> Dict[str, Any]:
        if not re.fullmatch(r"flash:sda-[A-Za-z0-9_-]+\.cfg", checkpoint):
            raise ConfigurationRejectedError("Checkpoint path is not managed by this service")
        connection = self._require_connection()
        output = str(
            connection.send_command_timing(
                "configure replace {} force".format(checkpoint),
                strip_prompt=False,
                strip_command=False,
            )
        )
        if CLI_ERROR.search(output):
            raise AdapterError("IOS XE configure-replace rollback failed")
        return {
            "checkpoint": checkpoint,
            "output_hash": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        }
