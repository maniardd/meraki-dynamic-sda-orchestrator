"""Runtime secret-provider boundary.

Secret references are resolved only inside the isolated apply worker. The API,
planner, renderer, evidence store, and logs never receive secret values.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, Mapping, Optional
from urllib.parse import unquote

import requests


SECRET_REFERENCE = re.compile(r"^secret://([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)(?:#([A-Za-z0-9_.-]+))?$")


class SecretProviderError(RuntimeError):
    pass


def _parse_reference(reference: str):
    match = SECRET_REFERENCE.fullmatch(str(reference))
    if not match:
        raise SecretProviderError("Invalid secret reference")
    return unquote(match.group(1)), unquote(match.group(2)) if match.group(2) else None


def _select(payload: Any, field: Optional[str]) -> Any:
    if field:
        if not isinstance(payload, Mapping) or field not in payload:
            raise SecretProviderError("Requested secret field is unavailable")
        return payload[field]
    return payload


class SecretProvider:
    provider_name = "abstract"

    def resolve(self, reference: str) -> Any:
        raise NotImplementedError

    def resolve_value(self, reference: str) -> str:
        value = self.resolve(reference)
        if isinstance(value, Mapping):
            value = value.get("value")
        rendered = str(value or "")
        if not rendered or "\n" in rendered or "\r" in rendered:
            raise SecretProviderError("Secret value is empty or invalid")
        return rendered

    def resolve_credentials(self, reference: str) -> Dict[str, str]:
        value = self.resolve(reference)
        if not isinstance(value, Mapping):
            raise SecretProviderError("Credential secret must be an object")
        username = str(value.get("username", ""))
        password = str(value.get("password", ""))
        if not username or not password:
            raise SecretProviderError("Credential secret requires username and password")
        result = {"username": username, "password": password}
        if value.get("enable_secret"):
            result["enable_secret"] = str(value["enable_secret"])
        return result


class StrictJsonFileSecretProvider(SecretProvider):
    """Host-local provider for an isolated lab, requiring a private 0600 file."""

    provider_name = "strict_json_file"

    def __init__(self, path: str):
        self.path = Path(path).expanduser().resolve()
        details = self.path.stat()
        if not stat.S_ISREG(details.st_mode):
            raise SecretProviderError("Secret path must be a regular file")
        if os.name != "nt" and details.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise SecretProviderError("Secret file must not be accessible by group or other")
        document = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise SecretProviderError("Secret file must contain a JSON object")
        self._document = document

    def resolve(self, reference: str) -> Any:
        path, field = _parse_reference(reference)
        if path not in self._document:
            raise SecretProviderError("Secret reference was not found")
        return _select(self._document[path], field)


class VaultKvSecretProvider(SecretProvider):
    """HashiCorp Vault KV v1/v2 HTTP provider with mandatory TLS verification."""

    provider_name = "vault_kv"

    def __init__(
        self,
        base_url: str,
        token_file: str,
        namespace: str = "",
        ca_bundle: str = "",
        timeout_seconds: int = 10,
    ):
        if not str(base_url).startswith("https://"):
            raise SecretProviderError("Vault URL must use HTTPS")
        self.base_url = str(base_url).rstrip("/")
        token_path = Path(token_file).expanduser().resolve()
        details = token_path.stat()
        if os.name != "nt" and details.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise SecretProviderError("Vault token file must have mode 0600")
        self._token = token_path.read_text(encoding="utf-8").strip()
        if not self._token:
            raise SecretProviderError("Vault token file is empty")
        self.namespace = str(namespace).strip()
        self.verify: Any = str(ca_bundle).strip() or True
        self.timeout_seconds = int(timeout_seconds)

    def resolve(self, reference: str) -> Any:
        path, field = _parse_reference(reference)
        headers = {"X-Vault-Token": self._token}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        response = requests.get(
            "{}/v1/{}".format(self.base_url, path),
            headers=headers,
            timeout=self.timeout_seconds,
            verify=self.verify,
        )
        if response.status_code != 200:
            raise SecretProviderError(
                "Vault did not return the requested secret (HTTP {})".format(
                    response.status_code
                )
            )
        body = response.json()
        payload = body.get("data") if isinstance(body, Mapping) else None
        if isinstance(payload, Mapping) and isinstance(payload.get("data"), Mapping):
            payload = payload["data"]
        if payload is None:
            raise SecretProviderError("Vault response has no secret data")
        return _select(payload, field)


def build_secret_provider(environment: Optional[Mapping[str, str]] = None) -> SecretProvider:
    values = dict(environment or os.environ)
    provider = str(values.get("ORCHESTRATOR_SECRET_PROVIDER", "")).strip().lower()
    if provider == "strict_json_file":
        return StrictJsonFileSecretProvider(str(values.get("ORCHESTRATOR_SECRET_FILE", "")))
    if provider == "vault_kv":
        return VaultKvSecretProvider(
            base_url=str(values.get("VAULT_ADDR", "")),
            token_file=str(values.get("VAULT_TOKEN_FILE", "")),
            namespace=str(values.get("VAULT_NAMESPACE", "")),
            ca_bundle=str(values.get("VAULT_CACERT", "")),
            timeout_seconds=int(values.get("VAULT_TIMEOUT_SECONDS", "10")),
        )
    raise SecretProviderError("A supported runtime secret provider is required")
