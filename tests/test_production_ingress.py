from __future__ import annotations

import unittest
from pathlib import Path

from tools.validate_ingress_handoff import validate


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "deploy" / "nginx" / "sda-orchestrator.conf.template"


def _render_template() -> str:
    return (
        TEMPLATE.read_text(encoding="utf-8")
        .replace("${ORCHESTRATOR_PUBLIC_FQDN}", "sda-poc.lab.example.com")
        .replace("${ORCHESTRATOR_TLS_CERTIFICATE_PATH}", "/etc/sda/tls/fullchain.pem")
        .replace("${ORCHESTRATOR_TLS_PRIVATE_KEY_PATH}", "/etc/sda/tls/private.key")
    )


class ProductionIngressTests(unittest.TestCase):
    def test_rendered_template_is_a_narrow_tls_only_handoff(self):
        self.assertEqual(validate(_render_template(), "sda-poc.lab.example.com"), [])

    def test_unresolved_placeholder_fails_closed(self):
        issues = validate(TEMPLATE.read_text(encoding="utf-8"), "sda-poc.lab.example.com")
        self.assertIn("configuration contains an unresolved deployment placeholder", issues)

    def test_ngrok_external_backend_and_apply_fail_closed(self):
        unsafe = _render_template().replace(
            "http://127.0.0.1:8080", "https://temporary.ngrok-free.app"
        ) + "\nlocation = /v1/workflow-actions/apply { return 200; }\n"
        issues = validate(unsafe, "sda-poc.lab.example.com")
        self.assertIn("forbidden ingress control: ngrok", issues)
        self.assertIn("production ingress must not expose an Apply workflow action", issues)
        self.assertIn("proxy backend must be the loopback-only API listener", issues)

    def test_ip_or_hostname_mismatch_fails_closed(self):
        rendered = _render_template()
        self.assertIn("hostname must be a DNS name, not an IP address", validate(rendered, "192.0.2.7"))
        self.assertIn(
            "server_name does not exactly match the requested hostname",
            validate(rendered, "other.lab.example.com"),
        )
