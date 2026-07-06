from __future__ import annotations

import unittest

from tools.meraki_discover import (
    DiscoveryError,
    MerakiReadOnlyClient,
    _next_link,
    discover,
)


class FakeResponse:
    def __init__(self, payload, status_code=200, headers=None):
        self.payload = payload
        self.status_code = status_code
        self.headers = headers or {}

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.headers = {}
        self.calls = []

    def get(self, url, params=None, timeout=None):
        self.calls.append({"url": url, "params": params, "timeout": timeout})
        if not self.responses:
            raise AssertionError(f"Unexpected GET {url}")
        return self.responses.pop(0)


class MerakiDiscoveryTests(unittest.TestCase):
    def test_missing_api_key_fails_closed(self):
        with self.assertRaises(DiscoveryError):
            MerakiReadOnlyClient("")

    def test_next_link_parser(self):
        header = '<https://api.meraki.com/api/v1/organizations?startingAfter=2>; rel="next"'
        self.assertEqual(
            "https://api.meraki.com/api/v1/organizations?startingAfter=2",
            _next_link(header),
        )

    def test_read_only_discovery_selects_sanitized_fields(self):
        session = FakeSession(
            [
                FakeResponse([{"id": "1", "name": "Lab", "unneeded": "discard"}]),
                FakeResponse(
                    [
                        {
                            "id": "N_1",
                            "name": "SDA-LAB",
                            "productTypes": ["switch"],
                            "timeZone": "Asia/Kolkata",
                            "unneeded": "discard",
                        }
                    ]
                ),
                FakeResponse(
                    [
                        {
                            "serial": "REDACTED-SERIAL",
                            "model": "C9300X",
                            "networkId": "N_1",
                            "mac": "must-not-be-exported",
                        }
                    ]
                ),
                FakeResponse(
                    [
                        {
                            "serial": "REDACTED-SERIAL",
                            "name": "EDGE-01",
                            "model": "C9300X",
                            "firmware": "17.18.3",
                            "networkId": "N_1",
                            "lanIp": "must-not-be-exported",
                        }
                    ]
                ),
            ]
        )
        client = MerakiReadOnlyClient("test-key", session=session)
        result = discover(client, organization_id="1", network_id="N_1")
        self.assertEqual("read-only", result["mode"])
        self.assertNotIn("unneeded", result["organizations"][0])
        self.assertNotIn("mac", result["inventory_devices"][0])
        self.assertNotIn("lanIp", result["network_devices"][0])
        self.assertTrue(session.headers["Authorization"].startswith("Bearer "))
        self.assertNotIn("test-key", str(result))


if __name__ == "__main__":
    unittest.main()
