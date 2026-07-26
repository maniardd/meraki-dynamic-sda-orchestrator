#!/usr/bin/env python3
"""Fail-closed preflight for a rendered SDA production ingress configuration.

This tool validates the narrow NGINX handoff contract before an operator asks
Meraki to use a permanent endpoint.  It does not edit the proxy, contact a
host, resolve DNS, or enable Apply.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path


_FQDN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
    re.IGNORECASE,
)
_REQUIRED_SNIPPETS = (
    "listen 443 ssl",
    "ssl_certificate ",
    "ssl_certificate_key ",
    "ssl_protocols TLSv1.2 TLSv1.3;",
    "proxy_pass http://127.0.0.1:8080;",
    "proxy_set_header X-Forwarded-Proto https;",
    "location = /health",
    "location = /ready",
    "location / {\n        return 404;",
)
_WORKFLOW_ACTIONS = (
    "plan",
    "approve",
    "run",
    "process-dry-run",
    "status",
    "evidence",
)
_FORBIDDEN = ("ngrok", "proxy_ssl_verify off", "ssl_verify_client off")


def validate(rendered: str, hostname: str) -> list[str]:
    """Return all contract violations without ever treating an unsafe config as valid."""
    issues: list[str] = []
    # Comments explain the contract and may mention forbidden words. Only
    # directives are security-relevant for this static preflight.
    directives = "\n".join(line.split("#", 1)[0] for line in rendered.splitlines())
    host = hostname.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        issues.append("hostname must be a DNS name, not an IP address")
    except ValueError:
        if not _FQDN.fullmatch(host) or host in {"localhost", "ngrok.io"}:
            issues.append("hostname must be a valid public FQDN")

    if "${" in directives or "__" in directives:
        issues.append("configuration contains an unresolved deployment placeholder")
    if f"server_name {host};" not in directives:
        issues.append("server_name does not exactly match the requested hostname")
    for required in _REQUIRED_SNIPPETS:
        if required not in directives:
            issues.append(f"missing required ingress control: {required}")
    for forbidden in _FORBIDDEN:
        if forbidden in directives.lower():
            issues.append(f"forbidden ingress control: {forbidden}")

    expected_actions = "|".join(_WORKFLOW_ACTIONS)
    if expected_actions not in directives:
        issues.append("workflow action allow-list is missing or broadened")
    if "apply" in directives.lower():
        issues.append("production ingress must not expose an Apply workflow action")
    if re.search(r"proxy_pass\s+https?://(?!127\.0\.0\.1:8080[;/])", directives):
        issues.append("proxy backend must be the loopback-only API listener")
    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="rendered NGINX server configuration")
    parser.add_argument("--hostname", required=True, help="approved public SDA FQDN")
    args = parser.parse_args(argv)
    try:
        rendered = args.config.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"ingress.preflight.error: {exc}", file=sys.stderr)
        return 2

    issues = validate(rendered, args.hostname)
    if issues:
        for issue in issues:
            print(f"ingress.preflight.failed: {issue}", file=sys.stderr)
        return 1
    print("ingress.preflight.passed: static handoff contract is safe to stage")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
