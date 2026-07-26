#!/usr/bin/env python3
"""Refresh the single temporary POC ngrok endpoint with fail-closed rollback."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


AGENT_API = "http://127.0.0.1:4040/api"
LOCAL_HEALTH = "http://127.0.0.1:8080/health"
EXPECTED_UPSTREAM = "http://localhost:8080"
NEW_TUNNEL_NAME = "sda-orchestrator-poc"


class PocIngressRepairError(RuntimeError):
    pass


def request_json(method: str, url: str, payload: dict[str, object] | None = None) -> tuple[int, dict[str, Any]]:
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={} if body is None else {"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # nosec B310 - fixed loopback or returned HTTPS endpoint
            raw = response.read()
            return response.status, {} if not raw else json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        document = {} if not raw else json.loads(raw.decode("utf-8"))
        return exc.code, document


def require_local_api_safe() -> None:
    status, health = request_json("GET", LOCAL_HEALTH)
    if status != 200 or health.get("status") != "ok" or health.get("execution_enabled") is not False:
        raise PocIngressRepairError("local API health or execution lock is not safe")


def get_single_tunnel() -> dict[str, Any]:
    status, document = request_json("GET", f"{AGENT_API}/tunnels")
    tunnels = document.get("tunnels")
    if status != 200 or not isinstance(tunnels, list) or len(tunnels) != 1:
        raise PocIngressRepairError("exactly one existing POC tunnel is required")
    tunnel = tunnels[0]
    if not isinstance(tunnel, dict):
        raise PocIngressRepairError("existing POC tunnel is invalid")
    name = tunnel.get("name")
    config = tunnel.get("config")
    if not isinstance(name, str) or not name or not isinstance(config, dict):
        raise PocIngressRepairError("existing POC tunnel lacks safe rollback metadata")
    addr = config.get("addr")
    if not isinstance(addr, str) or not addr.startswith("http://localhost:"):
        raise PocIngressRepairError("existing POC tunnel has an unsupported upstream")
    return {"name": name, "addr": addr}


def delete_tunnel(name: str) -> None:
    status, _ = request_json("DELETE", f"{AGENT_API}/tunnels/{urllib.parse.quote(name, safe='')}")
    if status not in (200, 204):
        raise PocIngressRepairError("tunnel delete did not succeed")


def start_tunnel(name: str, upstream: str) -> str:
    status, document = request_json(
        "POST",
        f"{AGENT_API}/tunnels",
        {"name": name, "addr": upstream, "proto": "http", "inspect": True},
    )
    public_url = document.get("public_url")
    parsed = urllib.parse.urlparse(str(public_url))
    if status != 201 or parsed.scheme != "https" or not parsed.hostname:
        raise PocIngressRepairError("new POC tunnel did not return a valid HTTPS URL")
    return str(public_url)


def require_public_health(public_url: str) -> None:
    status, health = request_json("GET", public_url.rstrip("/") + "/health")
    if status != 200 or health.get("status") != "ok" or health.get("execution_enabled") is not False:
        raise PocIngressRepairError("public POC health verification failed")


def main() -> int:
    rollback_attempted = False
    old_tunnel: dict[str, Any] | None = None
    try:
        require_local_api_safe()
        old_tunnel = get_single_tunnel()
        delete_tunnel(str(old_tunnel["name"]))
        public_url = start_tunnel(NEW_TUNNEL_NAME, EXPECTED_UPSTREAM)
        require_public_health(public_url)
        print(json.dumps({"result": "repaired", "public_url": public_url, "upstream": EXPECTED_UPSTREAM, "execution_enabled": False, "configuration_scope": "poc_tunnel_only", "contains_secret_values": False}, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, PocIngressRepairError) as exc:
        if old_tunnel is not None:
            rollback_attempted = True
            try:
                delete_tunnel(NEW_TUNNEL_NAME)
            except PocIngressRepairError:
                pass
            try:
                start_tunnel(str(old_tunnel["name"]), str(old_tunnel["addr"]))
            except PocIngressRepairError:
                pass
        print(json.dumps({"result": "failed", "error_type": type(exc).__name__, "rollback_attempted": rollback_attempted, "execution_enabled": False, "configuration_scope": "poc_tunnel_only", "contains_secret_values": False}, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
