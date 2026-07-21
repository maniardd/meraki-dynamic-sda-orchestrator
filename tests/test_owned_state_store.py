from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from orchestrator.intent import load_intent
from orchestrator.reconciliation import build_multicast_owned_state
from orchestrator.store import ConflictError, StateStore


ROOT = Path(__file__).resolve().parents[1]
LAB_INTENT = ROOT / "examples" / "fabric-intent.lab.yaml"


class OwnedStateStoreTests(unittest.TestCase):
    def test_adopted_baseline_requires_separate_discoverer_and_approver(self):
        intent = load_intent(LAB_INTENT)
        manifest = build_multicast_owned_state(intent)
        with tempfile.TemporaryDirectory() as temp_dir:
            store = StateStore(str(Path(temp_dir) / "owned-state.sqlite3"))
            with self.assertRaisesRegex(ConflictError, "different actors"):
                store.record_adopted_owned_state(
                    fabric_id=intent["fabric"]["id"],
                    manifest=manifest,
                    evidence_hash="e" * 64,
                    change_reference="CHG-BASELINE-1",
                    discovered_by="same-actor",
                    approver="same-actor",
                )
            baseline = store.record_adopted_owned_state(
                fabric_id=intent["fabric"]["id"],
                manifest=manifest,
                evidence_hash="e" * 64,
                change_reference="CHG-BASELINE-1",
                discovered_by="discovery-operator",
                approver="change-approver",
            )
            self.assertEqual("adopted_discovery", baseline["source_type"])
            self.assertEqual("e" * 64, baseline["evidence_hash"])
            self.assertEqual(manifest["manifest_hash"], baseline["manifest_hash"])
            self.assertEqual(
                baseline,
                store.latest_owned_state(intent["fabric"]["id"]),
            )
            self.assertTrue(store.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
