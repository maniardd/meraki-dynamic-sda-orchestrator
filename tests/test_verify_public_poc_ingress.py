from __future__ import annotations

import unittest
from pathlib import Path

from tools.verify_public_poc_ingress import health_url


ROOT = Path(__file__).resolve().parents[1]


class VerifyPublicPocIngressTests(unittest.TestCase):
    def test_only_a_plain_https_ngrok_origin_is_accepted(self):
        self.assertEqual("https://example.ngrok-free.dev/health", health_url("https://example.ngrok-free.dev"))
        for unsafe in ("http://example.ngrok-free.dev", "https://example.ngrok-free.dev/health", "https://example.invalid", "https://example.ngrok-free.dev?x=1"):
            with self.subTest(unsafe=unsafe):
                with self.assertRaises(ValueError):
                    health_url(unsafe)

    def test_workflow_runs_on_github_hosted_runner_without_secrets(self):
        workflow = (ROOT / ".github/workflows/verify_public_poc_ingress.yml").read_text(encoding="utf-8")
        self.assertIn("runs-on: ubuntu-latest", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("--origin \"${POC_ORIGIN}\"", workflow)
        self.assertNotIn("self-hosted", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("ssh", workflow.lower())


if __name__ == "__main__":
    unittest.main()
