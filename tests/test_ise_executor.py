from __future__ import annotations

import copy
import unittest
from urllib.parse import urlparse
from pathlib import Path

import yaml

from orchestrator.allocator import derive_fabric_intent
from orchestrator.ise import (
    IseCollisionError,
    IseErsAdapter,
    IseErsError,
    IseManifestError,
    IsePreflightError,
    IseRollbackError,
    IseVerificationError,
)
from orchestrator.planner import create_plan
from orchestrator.renderer import render_configuration


ROOT = Path(__file__).resolve().parents[1]


class FakeResponse:
    def __init__(self, status_code, body=None, headers=None):
        self.status_code = status_code
        self._body = body or {}
        self.headers = dict(headers or {})

    def json(self):
        return copy.deepcopy(self._body)


class FakeIseSession:
    ROOTS = {
        "sgt": "Sgt",
        "sgacl": "Sgacl",
        "egressmatrixcell": "EgressMatrixCell",
    }

    def __init__(self):
        self.auth = None
        self.headers = {}
        self.trust_env = True
        self.closed = False
        self.requests = []
        self.next_id = 1
        self.fail_write_resource = None
        self.cross_origin_location = False
        self.primary_role = "PrimaryAdmin"
        self.objects = {name: {} for name in self.ROOTS}
        self.objects["egressmatrixcell"]["default-cell"] = {
            "id": "default-cell",
            "name": "ANY-ANY",
            "description": "ISE default egress policy",
            "sourceSgtId": "any",
            "destinationSgtId": "any",
            "matrixCellStatus": "ENABLED",
            "defaultRule": "DENY_IP",
            "sgacls": [],
        }

    def close(self):
        self.closed = True

    @staticmethod
    def _filters(params):
        raw = (params or {}).get("filter", [])
        return [raw] if isinstance(raw, str) else list(raw)

    def _matches(self, item, filters):
        for value in filters:
            field, operator, expected = str(value).split(".", 2)
            if operator != "EQ" or str(item.get(field)) != expected:
                return False
        return True

    def request(
        self,
        method,
        url,
        params=None,
        json=None,
        headers=None,
        timeout=None,
        verify=None,
        allow_redirects=None,
    ):
        method = method.upper()
        path = urlparse(url).path
        call = {
            "method": method,
            "path": path,
            "params": copy.deepcopy(params),
            "json": copy.deepcopy(json),
            "headers": copy.deepcopy(headers),
            "timeout": timeout,
            "verify": verify,
            "allow_redirects": allow_redirects,
        }
        self.requests.append(call)
        if path == "/ers/config/sgt/versioninfo":
            return FakeResponse(200, {"VersionInfo": {}}, {"X-CSRF-Token": "csrf-1"})
        if path == "/api/v1/deployment/node":
            return FakeResponse(
                200,
                {
                    "response": [
                        {
                            "hostname": "ise-01.example.test",
                            "ipAddress": "192.0.2.10",
                            "roles": [self.primary_role],
                        }
                    ]
                },
            )
        parts = [part for part in path.split("/") if part]
        if len(parts) < 3 or parts[:2] != ["ers", "config"]:
            return FakeResponse(404)
        resource = parts[2]
        if resource not in self.ROOTS:
            return FakeResponse(404)
        root = self.ROOTS[resource]
        if method == "GET" and len(parts) == 3:
            matches = [
                item
                for item in self.objects[resource].values()
                if self._matches(item, self._filters(params))
            ]
            return FakeResponse(
                200,
                {
                    "SearchResult": {
                        "total": len(matches),
                        "resources": [
                            {"id": item["id"], "name": item.get("name", "")}
                            for item in matches
                        ],
                    }
                },
            )
        resource_id = parts[3] if len(parts) == 4 else None
        if method == "GET" and resource_id:
            item = self.objects[resource].get(resource_id)
            return FakeResponse(200, {root: item}) if item else FakeResponse(404)
        if method in {"POST", "PUT", "DELETE"}:
            if (headers or {}).get("X-CSRF-Token") != "csrf-1":
                return FakeResponse(403)
            if self.fail_write_resource == resource:
                self.fail_write_resource = None
                return FakeResponse(500)
        if method == "POST" and len(parts) == 3:
            item = copy.deepcopy((json or {})[root])
            resource_id = "{}-{}".format(resource, self.next_id)
            self.next_id += 1
            item["id"] = resource_id
            self.objects[resource][resource_id] = item
            origin = "https://evil.example.test" if self.cross_origin_location else ""
            return FakeResponse(
                201,
                headers={"Location": "{}/ers/config/{}/{}".format(origin, resource, resource_id)},
            )
        if method == "PUT" and resource_id:
            if resource_id not in self.objects[resource]:
                return FakeResponse(404)
            item = copy.deepcopy((json or {})[root])
            item["id"] = resource_id
            self.objects[resource][resource_id] = item
            return FakeResponse(204)
        if method == "DELETE" and resource_id:
            self.objects[resource].pop(resource_id, None)
            return FakeResponse(204)
        return FakeResponse(405)

    @property
    def writes(self):
        return [item for item in self.requests if item["method"] in {"POST", "PUT", "DELETE"}]


def manifest():
    marker = "managed-by:meraki-dynamic-sda"
    return {
        "type": "cisco_ise_ers",
        "executor_contract_version": "1.0",
        "contains_secret_values": False,
        "write_node_id": "ise-01",
        "write_node_address": "192.0.2.10",
        "api_base_url": "https://ise-01.example.test",
        "credential_ref": "secret://test/ise",
        "tls_verify": True,
        "csrf_mode": "auto",
        "ownership": {
            "marker": marker,
            "unmanaged_collision": "fail",
            "delete_policy": "new_owned_resources_only_during_verified_rollback",
        },
        "preconditions": [
            "ers_read_write_enabled",
            "write_node_is_primary_pan",
            "trusted_tls_chain",
            "default_egress_matrix_is_deny",
        ],
        "operations": [
            {
                "operation_id": "ise-sgt-corp",
                "resource": "sgt",
                "strategy": "upsert_owned_by_name",
                "collision_policy": "fail_if_unmanaged",
                "lookup": {"name": "CORP"},
                "desired": {
                    "name": "CORP",
                    "value": 1000,
                    "description": marker,
                    "propogateToApic": False,
                },
            },
            {
                "operation_id": "ise-sgt-guest",
                "resource": "sgt",
                "strategy": "upsert_owned_by_name",
                "collision_policy": "fail_if_unmanaged",
                "lookup": {"name": "GUEST"},
                "desired": {
                    "name": "GUEST",
                    "value": 1001,
                    "description": marker,
                    "propogateToApic": False,
                },
            },
            {
                "operation_id": "ise-sgacl-web",
                "resource": "sgacl",
                "strategy": "upsert_owned_by_name",
                "collision_policy": "fail_if_unmanaged",
                "lookup": {"name": "WEB"},
                "desired": {
                    "name": "WEB",
                    "description": marker + " contract:web",
                    "ipVersion": "IPV4",
                    "aclcontent": "permit tcp dst eq 443\ndeny ip",
                },
            },
            {
                "operation_id": "ise-cell-corp-guest",
                "resource": "egressmatrixcell",
                "strategy": "upsert_owned_by_sgt_pair",
                "collision_policy": "fail_if_unmanaged",
                "lookup": {
                    "source_sgt_name": "CORP",
                    "destination_sgt_name": "GUEST",
                },
                "desired": {
                    "description": marker + " contract:web",
                    "matrixCellStatus": "ENABLED",
                    "defaultRule": "NONE",
                    "sgacl_name_refs": ["WEB"],
                },
            },
        ],
        "rollback": "restore_prechange_snapshots_and_delete_only_new_owned_resources",
    }


class IseExecutorTests(unittest.TestCase):
    def adapter(self, session, document=None):
        return IseErsAdapter(
            document or manifest(),
            lambda _reference: {"username": "ers-admin", "password": "test-password"},
            lambda _reference: "unused",
            session_factory=lambda: session,
        )

    def test_create_verify_reference_resolution_and_reverse_rollback(self):
        session = FakeIseSession()
        adapter = self.adapter(session)
        adapter.connect()
        prepared = adapter.prepare()
        self.assertTrue(prepared["verified"])
        self.assertEqual(
            {"create": 3, "update": 0, "noop": 0, "deferred": 1},
            prepared["action_counts"],
        )
        result = adapter.apply()
        self.assertTrue(result["verified"])
        self.assertEqual(4, result["changed_count"])
        cell = next(
            item
            for key, item in session.objects["egressmatrixcell"].items()
            if key != "default-cell"
        )
        self.assertEqual(session.objects["sgt"]["sgt-1"]["id"], cell["sourceSgtId"])
        self.assertEqual(session.objects["sgt"]["sgt-2"]["id"], cell["destinationSgtId"])
        self.assertEqual([session.objects["sgacl"]["sgacl-3"]["id"]], cell["sgacls"])
        for request in session.writes:
            self.assertEqual("csrf-1", request["headers"].get("X-CSRF-Token"))
            self.assertTrue(request["verify"])
            self.assertFalse(request["allow_redirects"])
            self.assertEqual((10, 30), request["timeout"])
        rollback = adapter.rollback()
        self.assertTrue(rollback["verified"])
        self.assertFalse(adapter.has_changes)
        self.assertEqual({}, session.objects["sgt"])
        self.assertEqual({}, session.objects["sgacl"])
        self.assertEqual(["default-cell"], list(session.objects["egressmatrixcell"]))
        adapter.close()
        self.assertTrue(session.closed)
        self.assertFalse(session.trust_env)

    def test_manifest_contract_rejects_unsafe_or_ambiguous_inputs(self):
        mutations = [
            lambda value: value.update({"tls_verify": False}),
            lambda value: value.update({"api_base_url": "https://user:pass@ise.example.test"}),
            lambda value: value["ownership"].update({"unmanaged_collision": "overwrite"}),
            lambda value: value["operations"][0]["desired"].update(
                {"description": "managed-by:meraki-dynamic-sda secret://leak"}
            ),
            lambda value: value["operations"][0]["desired"].update({"value": 65536}),
            lambda value: value["operations"][3]["desired"].update(
                {"defaultRule": "PERMIT_IP"}
            ),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                document = manifest()
                mutation(document)
                with self.assertRaises(IseManifestError):
                    self.adapter(FakeIseSession(), document)

    def test_cop29_scale_renderer_emits_an_accepted_executor_contract(self):
        requirements = yaml.safe_load(
            (ROOT / "examples" / "fabric-requirements.cop29-sanitized.yaml").read_text(
                encoding="utf-8"
            )
        )
        policy = yaml.safe_load(
            (ROOT / "policy" / "guardrails.cop29-sanitized.yaml").read_text(
                encoding="utf-8"
            )
        )
        intent = derive_fabric_intent(requirements, policy)["intent"]
        rendered = render_configuration(intent, create_plan(intent))
        adapter = self.adapter(FakeIseSession(), rendered["external_systems"]["ise"])
        self.assertEqual("1.0", adapter.manifest["executor_contract_version"])
        self.assertEqual(10, len(adapter.manifest["operations"]))

    def test_unmanaged_name_collision_fails_before_first_write(self):
        session = FakeIseSession()
        session.objects["sgt"]["manual"] = {
            "id": "manual",
            "name": "CORP",
            "value": 1000,
            "description": "created by an administrator",
            "propogateToApic": False,
        }
        adapter = self.adapter(session)
        adapter.connect()
        with self.assertRaises(IseCollisionError):
            adapter.prepare()
        self.assertEqual([], session.writes)

    def test_duplicate_sgt_value_fails_before_first_write(self):
        session = FakeIseSession()
        session.objects["sgt"]["other"] = {
            "id": "other",
            "name": "OTHER",
            "value": 1000,
            "description": "managed-by:meraki-dynamic-sda",
            "propogateToApic": False,
        }
        adapter = self.adapter(session)
        adapter.connect()
        with self.assertRaisesRegex(IseCollisionError, "value"):
            adapter.prepare()
        self.assertEqual([], session.writes)

    def test_owned_update_restores_prechange_snapshot(self):
        session = FakeIseSession()
        document = manifest()
        document["operations"] = [document["operations"][0]]
        session.objects["sgt"]["existing"] = {
            "id": "existing",
            "name": "CORP",
            "value": 1000,
            "description": "managed-by:meraki-dynamic-sda previous",
            "propogateToApic": True,
        }
        original = copy.deepcopy(session.objects["sgt"]["existing"])
        adapter = self.adapter(session, document)
        adapter.connect()
        prepared = adapter.prepare()
        self.assertEqual(1, prepared["action_counts"]["update"])
        adapter.apply()
        self.assertFalse(session.objects["sgt"]["existing"]["propogateToApic"])
        adapter.rollback()
        self.assertEqual(original, session.objects["sgt"]["existing"])

    def test_partial_failure_keeps_journal_for_verified_rollback(self):
        session = FakeIseSession()
        session.fail_write_resource = "sgacl"
        adapter = self.adapter(session)
        adapter.connect()
        adapter.prepare()
        with self.assertRaises(IseErsError):
            adapter.apply()
        self.assertTrue(adapter.has_changes)
        self.assertEqual(2, len(session.objects["sgt"]))
        self.assertTrue(adapter.rollback()["verified"])
        self.assertEqual({}, session.objects["sgt"])

    def test_primary_pan_and_default_deny_preconditions_fail_closed(self):
        session = FakeIseSession()
        session.primary_role = "SecondaryAdmin"
        adapter = self.adapter(session)
        adapter.connect()
        with self.assertRaisesRegex(IsePreflightError, "PrimaryAdmin"):
            adapter.prepare()
        self.assertEqual([], session.writes)

        session = FakeIseSession()
        session.objects["egressmatrixcell"]["default-cell"]["defaultRule"] = "PERMIT_IP"
        adapter = self.adapter(session)
        adapter.connect()
        with self.assertRaisesRegex(IsePreflightError, "not deny"):
            adapter.prepare()
        self.assertEqual([], session.writes)

    def test_cross_origin_create_location_is_rejected_and_never_followed(self):
        session = FakeIseSession()
        session.cross_origin_location = True
        document = manifest()
        document["operations"] = [document["operations"][0]]
        adapter = self.adapter(session, document)
        adapter.connect()
        adapter.prepare()
        with self.assertRaises(IseVerificationError):
            adapter.apply()
        self.assertTrue(
            all("evil.example.test" not in item["path"] for item in session.requests)
        )
        self.assertTrue(adapter.has_changes)
        self.assertTrue(adapter.rollback()["verified"])
        self.assertEqual({}, session.objects["sgt"])

    def test_out_of_band_change_refuses_destructive_rollback(self):
        session = FakeIseSession()
        document = manifest()
        document["operations"] = [document["operations"][0]]
        adapter = self.adapter(session, document)
        adapter.connect()
        adapter.prepare()
        adapter.apply()
        session.objects["sgt"]["sgt-1"]["description"] += " changed-out-of-band"
        with self.assertRaises(IseRollbackError):
            adapter.rollback()
        self.assertIn("sgt-1", session.objects["sgt"])
        self.assertTrue(adapter.has_changes)


if __name__ == "__main__":
    unittest.main()
