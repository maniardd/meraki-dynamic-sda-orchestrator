from __future__ import annotations

import unittest
from pathlib import Path

from tools.inspect_poc_ingress import summarize_tunnels


class InspectPocIngressTests(unittest.TestCase):
    def test_tunnel_summary_contains_only_connectivity_metadata(self):
        summary = summarize_tunnels(
            {
                "tunnels": [
                    {
                        "public_url": "https://example.ngrok-free.dev",
                        "config": {"addr": "localhost:8080", "auth": "must-not-leak"},
                    }
                ]
            }
        )
        self.assertEqual(
            [{"protocol": "https", "public_host": "example.ngrok-free.dev", "upstream_host": "localhost", "upstream_port": 8080}],
            summary,
        )
        self.assertNotIn("must-not-leak", str(summary))

    def test_incomplete_tunnel_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "incomplete tunnel"):
            summarize_tunnels({"tunnels": [{"public_url": "https://example.ngrok-free.dev", "config": {}}]})

    def test_workflow_is_manual_and_read_only(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/inspect_poc_ingress.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("runs-on: [self-hosted, sda-relay]", workflow)
        self.assertNotIn("sudo", workflow)
        self.assertNotIn("systemctl restart", workflow)
        self.assertNotIn("ngrok config", workflow)


if __name__ == "__main__":
    unittest.main()
