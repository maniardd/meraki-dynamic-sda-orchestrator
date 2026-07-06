#!/usr/bin/env python3
"""Read-only Meraki organization, network, and device discovery.

The tool never performs POST, PUT, PATCH, or DELETE operations and never prints
the API credential. It is the first integration gate before any Meraki write
permissions or deployment activity are considered.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests
from dotenv import load_dotenv


DEFAULT_BASE_URL = "https://api.meraki.com/api/v1"
TIMEOUT_SECONDS = 30


class DiscoveryError(RuntimeError):
    pass


def load_configuration(secrets_file: Optional[str] = None) -> None:
    """Load non-secret project settings, then an optional external secret file."""
    load_dotenv()
    if not secrets_file:
        return
    path = Path(secrets_file).expanduser()
    if not path.is_file():
        raise DiscoveryError(f"Secrets file does not exist: {path}")
    load_dotenv(dotenv_path=path, override=True)


def get_api_key() -> str:
    return os.getenv("MERAKI_DASHBOARD_API_KEY") or os.getenv("MERAKI_API_KEY", "")


def get_base_url() -> str:
    return os.getenv("MERAKI_BASE_URL", DEFAULT_BASE_URL).rstrip("/")


def _next_link(link_header: str) -> Optional[str]:
    for part in link_header.split(","):
        section = part.strip()
        if 'rel="next"' not in section:
            continue
        start = section.find("<")
        end = section.find(">", start + 1)
        if start >= 0 and end > start:
            return section[start + 1 : end]
    return None


class MerakiReadOnlyClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        session: Optional[requests.Session] = None,
    ):
        if not api_key:
            raise DiscoveryError(
                "Set MERAKI_DASHBOARD_API_KEY in the local .env file or environment"
            )
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
                "User-Agent": "sda-production-foundation/0.1 read-only-discovery",
            }
        )

    def get_paginated(self, path: str) -> List[Any]:
        url = path
        params: Optional[Dict[str, Any]] = {"perPage": 1000}
        items: List[Any] = []
        while url:
            full_url = url if url.startswith("https://") else f"{self.base_url}{url}"
            response = self.session.get(full_url, params=params, timeout=TIMEOUT_SECONDS)
            if response.status_code >= 400:
                request_id = response.headers.get("X-Request-Id", "unavailable")
                raise DiscoveryError(
                    f"GET {path} failed with HTTP {response.status_code}; request_id={request_id}"
                )
            try:
                page = response.json()
            except ValueError as exc:
                raise DiscoveryError(f"GET {path} returned invalid JSON") from exc
            if not isinstance(page, list):
                raise DiscoveryError(f"GET {path} did not return a list")
            items.extend(page)
            url = _next_link(response.headers.get("Link", "")) or ""
            params = None
        return items


def _select_fields(items: Iterable[Dict[str, Any]], fields: Iterable[str]) -> List[Dict[str, Any]]:
    return [
        {field: item.get(field) for field in fields if field in item}
        for item in items
    ]


def discover(
    client: MerakiReadOnlyClient,
    organization_id: Optional[str] = None,
    network_id: Optional[str] = None,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "discovered_at": datetime.now(timezone.utc).isoformat(),
        "mode": "read-only",
        "base_url": client.base_url,
    }

    organizations = client.get_paginated("/organizations")
    result["organizations"] = _select_fields(
        organizations,
        ("id", "name", "url", "api"),
    )

    networks: List[Dict[str, Any]] = []
    if organization_id:
        organization_ids = {str(item.get("id")) for item in organizations}
        if organization_id not in organization_ids:
            raise DiscoveryError(
                f"Token cannot see organization {organization_id}; check role and organization ID"
            )
        networks = client.get_paginated(f"/organizations/{organization_id}/networks")
        result["selected_organization_id"] = organization_id
        result["networks"] = _select_fields(
            networks,
            ("id", "name", "productTypes", "tags", "timeZone", "isBoundToConfigTemplate"),
        )
        inventory = client.get_paginated(f"/organizations/{organization_id}/inventory/devices")
        result["inventory_devices"] = _select_fields(
            inventory,
            ("serial", "name", "model", "networkId", "productType", "claimedAt", "countryCode"),
        )

    if network_id:
        if not organization_id:
            raise DiscoveryError("--network-id requires --organization-id")
        visible_networks = {str(item.get("id")) for item in networks}
        if network_id not in visible_networks:
            raise DiscoveryError(
                f"Network {network_id} is not visible in organization {organization_id}"
            )
        devices = client.get_paginated(f"/networks/{network_id}/devices")
        result["selected_network_id"] = network_id
        result["network_devices"] = _select_fields(
            devices,
            ("serial", "name", "model", "firmware", "networkId", "productType", "tags", "address"),
        )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--secrets-file",
        help="Optional dotenv file outside the repository containing the read-only API key",
    )
    parser.add_argument("--organization-id", help="Discover networks and inventory in this organization")
    parser.add_argument("--network-id", help="Also discover assigned devices in this network")
    parser.add_argument("--output", help="Optional path for sanitized *.inventory.json output")
    args = parser.parse_args()

    try:
        load_configuration(args.secrets_file)
        client = MerakiReadOnlyClient(get_api_key(), get_base_url())
        result = discover(client, args.organization_id, args.network_id)
    except (DiscoveryError, requests.RequestException) as exc:
        print(f"DISCOVERY ERROR: {exc}", file=sys.stderr)
        return 1

    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        destination = Path(args.output)
        if not destination.name.endswith(".inventory.json"):
            print("OUTPUT ERROR: output filename must end with .inventory.json", file=sys.stderr)
            return 2
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rendered + "\n", encoding="utf-8")
        print(f"Saved read-only inventory to {destination}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
