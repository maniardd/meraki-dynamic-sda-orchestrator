#!/usr/bin/env python3
"""Inspect the POC HTTPS tunnel and local API without changing either."""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlparse


TUNNEL_API = "http://127.0.0.1:4040/api/tunnels"
API_HEALTH = "http://127.0.0.1:8080/health"
SERVICE_UNITS = ("ngrok.service", "ngrok-agent.service")


def _read_json(url: str) -> dict[str, object]:
    with urllib.request.urlopen(url, timeout=5) as response:  # nosec B310 - fixed loopback URL
        payload = response.read()
    document = json.loads(payload.decode("utf-8"))
    if not isinstance(document, dict):
        raise ValueError("loopback endpoint returned a non-object JSON value")
    return document


def summarize_tunnels(document: dict[str, object]) -> list[dict[str, object]]:
    """Return URL and upstream endpoint metadata only; never configuration values."""

    tunnels = document.get("tunnels")
    if not isinstance(tunnels, list):
        raise ValueError("tunnel API response did not contain a tunnel list")
    summaries: list[dict[str, object]] = []
    for tunnel in tunnels:
        if not isinstance(tunnel, dict):
            raise ValueError("tunnel API response contained an invalid tunnel")
        public_url = str(tunnel.get("public_url", ""))
        public = urlparse(public_url)
        config = tunnel.get("config")
        if not public.scheme or not public.hostname or not isinstance(config, dict):
            raise ValueError("tunnel API response contained an incomplete tunnel")
        raw_upstream = str(config.get("addr", ""))
        upstream = urlparse(
            raw_upstream if "://" in raw_upstream else "//" + raw_upstream
        )
        if not upstream.hostname or upstream.port is None:
            raise ValueError("tunnel API response contained an incomplete tunnel")
        summaries.append(
            {
                "protocol": public.scheme,
                "public_host": public.hostname,
                "upstream_host": upstream.hostname,
                "upstream_port": upstream.port,
            }
        )
    return summaries


def service_state(unit: str) -> str:
    completed = subprocess.run(
        ["systemctl", "is-active", unit],
        check=False,
        capture_output=True,
        text=True,
    )
    state = completed.stdout.strip()
    return state if state else "unknown"


def ngrok_process_owners() -> list[str]:
    """Return only owners of ngrok processes, never their command lines."""

    completed = subprocess.run(
        ["ps", "-C", "ngrok", "-o", "user="],
        check=False,
        capture_output=True,
        text=True,
    )
    return sorted({line.strip() for line in completed.stdout.splitlines() if line.strip()})


def main() -> int:
    try:
        tunnel_document = _read_json(TUNNEL_API)
        health = _read_json(API_HEALTH)
        tunnels = summarize_tunnels(tunnel_document)
        report = {
            "schema_version": "1.0",
            "inspection_mode": "read_only",
            "tunnel_count": len(tunnels),
            "tunnels": tunnels,
            "api_health_status": health.get("status"),
            "execution_enabled": health.get("execution_enabled"),
            "service_states": {unit: service_state(unit) for unit in SERVICE_UNITS},
            "ngrok_process_owners": ngrok_process_owners(),
            "contains_secret_values": False,
            "configuration_changed": False,
        }
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        report = {
            "schema_version": "1.0",
            "inspection_mode": "read_only",
            "safe": False,
            "error_type": type(exc).__name__,
            "contains_secret_values": False,
            "configuration_changed": False,
        }
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
