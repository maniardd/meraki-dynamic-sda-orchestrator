#!/usr/bin/env python3
"""Verify a temporary ngrok POC endpoint from a GitHub-hosted runner."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from urllib.parse import urlparse


def health_url(origin: str) -> str:
    parsed = urlparse(origin)
    if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(".ngrok-free.dev"):
        raise ValueError("origin must be an HTTPS ngrok-free.dev hostname")
    if parsed.path not in ("", "/") or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("origin must not include a path, query, or fragment")
    return f"https://{parsed.hostname}/health"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    arguments = parser.parse_args()
    try:
        url = health_url(arguments.origin)
        with urllib.request.urlopen(url, timeout=15) as response:  # nosec B310 - validated HTTPS ngrok hostname
            status = response.status
            health = json.loads(response.read().decode("utf-8"))
        if status != 200 or health.get("status") != "ok" or health.get("execution_enabled") is not False:
            raise ValueError("public health response is not safe")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"result": "failed", "error_type": type(exc).__name__, "contains_secret_values": False}, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps({"result": "passed", "public_host": urlparse(url).hostname, "execution_enabled": False, "contains_secret_values": False}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
