"""Transactional apply worker with prechecks, checkpoints, gates, and rollback.

The API does not instantiate this worker. Production enablement requires a
separate bounded worker process, secret resolver, queue, and explicit runtime
flag. Unit tests use fake adapters only.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Mapping, Optional

from .gates import build_gate_plan, evaluate_gate
from .store import ConflictError, StateStore, sha256_json


SECRET_PLACEHOLDER = re.compile(r"<secret:(secret://[^>]+)>")


class WorkerError(RuntimeError):
    pass


def _resolve_commands(commands: List[str], resolver: Callable[[str], str]) -> List[str]:
    resolved: List[str] = []
    for command in commands:
        def replace(match):
            value = str(resolver(match.group(1)))
            if not value or "\n" in value or "\r" in value:
                raise WorkerError("Secret resolver returned an invalid value")
            return value

        rendered = SECRET_PLACEHOLDER.sub(replace, str(command))
        if "<secret:" in rendered:
            raise WorkerError("Unresolved secret placeholder")
        resolved.append(rendered)
    return resolved


class TransactionWorker:
    def __init__(
        self,
        store: StateStore,
        adapter_factory: Callable[[Mapping[str, Any]], Any],
        secret_resolver: Callable[[str], str],
        actor: str = "sda-worker",
        ise_adapter_factory: Optional[Callable[[Mapping[str, Any]], Any]] = None,
    ):
        self.store = store
        self.adapter_factory = adapter_factory
        self.secret_resolver = secret_resolver
        self.actor = actor
        self.ise_adapter_factory = ise_adapter_factory

    def _record_gate(
        self,
        run_id: str,
        gate: Mapping[str, Any],
        adapter: Any,
    ) -> bool:
        response = adapter.run_show(str(gate["command"]))
        result = evaluate_gate(gate, str(response["output"]))
        self.store.add_evidence(
            run_id=run_id,
            phase_id=str(gate["phase_id"]),
            device_id=str(gate["device_id"]),
            evidence_type="operational_gate",
            payload={
                "gate_id": gate["gate_id"],
                "command": gate["command"],
                "output_hash": response["output_hash"],
                "passed": result.passed,
                "reason": result.reason,
                "observations": result.observations,
            },
            actor=self.actor,
        )
        return result.passed

    def process_apply(
        self,
        run_id: str,
        intent: Mapping[str, Any],
        plan: Mapping[str, Any],
        artifact: Mapping[str, Any],
    ) -> Dict[str, Any]:
        run = self.store.get_run(run_id)
        if run["mode"] != "apply" or run["status"] != "apply_queued":
            raise ConflictError("Run is not queued for apply")
        artifact_body = dict(artifact)
        supplied_artifact_hash = str(artifact_body.pop("artifact_hash", ""))
        if (
            len(supplied_artifact_hash) != 64
            or sha256_json(artifact_body) != supplied_artifact_hash
            or supplied_artifact_hash != str(run["artifact_hash"])
        ):
            raise ConflictError("Artifact integrity or run binding check failed")
        if (
            str(artifact.get("plan_hash")) != str(run["plan_hash"])
            or str(plan.get("plan_hash")) != str(run["plan_hash"])
        ):
            raise ConflictError("Plan integrity or run binding check failed")
        if artifact.get("blocking_requirements"):
            updated = self.store.transition_run(
                run_id,
                "apply_failed",
                self.actor,
                {"reason": "artifact_has_blocking_requirements"},
            )
            return {"succeeded": False, "run": updated, "rolled_back": False}

        devices = {str(device["id"]): dict(device) for device in intent["devices"]}
        for fusion in intent.get("fusion_nodes", []):
            fusion_device = dict(fusion)
            fusion_device["roles"] = ["fusion"]
            devices[str(fusion_device["id"])] = fusion_device
        for device_id, artifact_device in artifact.get("devices", {}).items():
            if device_id in devices:
                continue
            if not artifact_device.get("retired_target"):
                raise WorkerError("Artifact contains an unknown active device")
            descriptor = artifact_device.get("device_descriptor")
            if not isinstance(descriptor, dict) or str(descriptor.get("id")) != str(
                device_id
            ):
                raise WorkerError("Retired reconciliation target is invalid")
            devices[str(device_id)] = dict(descriptor)
        adapters: Dict[str, Any] = {}
        checkpoints: Dict[str, str] = {}
        gate_plan = build_gate_plan(intent, artifact)
        changed_devices: List[str] = []
        ise_manifest = (artifact.get("external_systems") or {}).get("ise")
        ise_adapter = None
        ise_applied = False
        self.store.transition_run(run_id, "apply_running", self.actor)
        try:
            for device_id in sorted(devices):
                adapter = self.adapter_factory(devices[device_id])
                adapter.connect()
                adapters[device_id] = adapter

            if ise_manifest:
                if self.ise_adapter_factory is None:
                    raise WorkerError("ISE manifest requires an enabled ISE executor")
                ise_adapter = self.ise_adapter_factory(ise_manifest)
                ise_adapter.connect()
                preflight = ise_adapter.prepare()
                if not preflight.get("verified"):
                    raise WorkerError("ISE preflight did not return verified evidence")
                self.store.add_evidence(
                    run_id=run_id,
                    phase_id="precheck",
                    device_id=str(ise_manifest["write_node_id"]),
                    evidence_type="ise_ers_preflight",
                    payload=preflight,
                    actor=self.actor,
                )

            prechecks = [gate for gate in gate_plan if gate["phase_id"] == "precheck"]
            for gate in prechecks:
                if not self._record_gate(run_id, gate, adapters[str(gate["device_id"])]):
                    updated = self.store.transition_run(
                        run_id,
                        "apply_failed",
                        self.actor,
                        {"reason": "precheck_failed", "gate_id": gate["gate_id"]},
                    )
                    return {"succeeded": False, "run": updated, "rolled_back": False}

            for device_id in sorted(adapters):
                checkpoint = adapters[device_id].create_checkpoint(run_id)
                if not checkpoint.get("verified"):
                    raise WorkerError("Checkpoint verification failed")
                checkpoints[device_id] = str(checkpoint["checkpoint"])
                self.store.add_evidence(
                    run_id=run_id,
                    phase_id="checkpoint",
                    device_id=device_id,
                    evidence_type="device_checkpoint",
                    payload=checkpoint,
                    actor=self.actor,
                )

            artifact_devices = artifact["devices"]
            ordered_phases = [
                str(phase["id"])
                for phase in plan["phases"]
                if str(phase["id"])
                not in {"precheck", "checkpoint", "endpoint_assurance"}
            ]
            for phase_id in ordered_phases:
                if phase_id == "policy_plane" and ise_adapter is not None:
                    # ISE policy objects must be verified before the devices
                    # are asked to consume or enforce the new policy.
                    ise_result = ise_adapter.apply()
                    if not ise_result.get("verified"):
                        raise WorkerError("ISE apply did not return verified evidence")
                    ise_applied = True
                    self.store.add_evidence(
                        run_id=run_id,
                        phase_id=phase_id,
                        device_id=str(ise_manifest["write_node_id"]),
                        evidence_type="ise_ers_transaction",
                        payload=ise_result,
                        actor=self.actor,
                    )
                for device_id in sorted(artifact_devices):
                    phase = next(
                        (
                            item
                            for item in artifact_devices[device_id]["phases"]
                            if item["phase_id"] == phase_id
                        ),
                        None,
                    )
                    if not phase:
                        continue
                    for block in phase["blocks"]:
                        commands = _resolve_commands(
                            list(block["commands"]), self.secret_resolver
                        )
                        # Mark before sending because a transport or parser
                        # failure can occur after IOS XE partially accepts a block.
                        if device_id not in changed_devices:
                            changed_devices.append(device_id)
                        evidence = adapters[device_id].apply_block(commands)
                        self.store.add_evidence(
                            run_id=run_id,
                            phase_id=phase_id,
                            device_id=device_id,
                            evidence_type="configuration_block",
                            payload={
                                "block_id": block["block_id"],
                                "rendered_command_hash": block["command_hash"],
                                "applied_command_hash": evidence["command_hash"],
                                "command_count": evidence["command_count"],
                                "output_hash": evidence["output_hash"],
                            },
                            actor=self.actor,
                        )
                phase_gates = [gate for gate in gate_plan if gate["phase_id"] == phase_id]
                for gate in phase_gates:
                    if not self._record_gate(run_id, gate, adapters[str(gate["device_id"])]):
                        raise WorkerError("Operational gate failed")

            if ise_adapter is not None and not ise_applied:
                raise WorkerError("ISE manifest was not bound to the policy_plane phase")

            updated = self.store.complete_apply(
                run_id,
                str(artifact["artifact_hash"]),
                artifact["owned_state"],
                self.actor,
                {
                    "changed_devices": sorted(changed_devices),
                    "changed_external_systems": ["ise"]
                    if ise_adapter is not None and ise_adapter.has_changes
                    else [],
                },
            )
            plan_record = self.store.get_plan(str(run["plan_id"]))
            if plan_record.get("reservation_id"):
                self.store.transition_design_reservation(
                    str(plan_record["reservation_id"]),
                    "committed",
                    self.actor,
                )
            return {"succeeded": True, "run": updated, "rolled_back": False}
        except Exception as exc:
            ise_has_changes = bool(
                ise_adapter is not None and getattr(ise_adapter, "has_changes", False)
            )
            if checkpoints or ise_has_changes:
                self.store.transition_run(
                    run_id,
                    "rollback_running",
                    self.actor,
                    {"failure_type": type(exc).__name__},
                )
                rollback_failures = []
                for device_id in reversed(changed_devices or sorted(checkpoints)):
                    try:
                        result = adapters[device_id].rollback(checkpoints[device_id])
                        if not result.get("verified"):
                            raise WorkerError("Rollback did not return verified evidence")
                        self.store.add_evidence(
                            run_id=run_id,
                            phase_id="rollback",
                            device_id=device_id,
                            evidence_type="configure_replace",
                            payload=result,
                            actor=self.actor,
                        )
                    except Exception as rollback_error:
                        rollback_failures.append(
                            {"device_id": device_id, "error_type": type(rollback_error).__name__}
                        )
                if ise_has_changes:
                    try:
                        result = ise_adapter.rollback()
                        if not result.get("verified"):
                            raise WorkerError("ISE rollback did not return verified evidence")
                        self.store.add_evidence(
                            run_id=run_id,
                            phase_id="rollback",
                            device_id=str(ise_manifest["write_node_id"]),
                            evidence_type="ise_ers_rollback",
                            payload=result,
                            actor=self.actor,
                        )
                    except Exception as rollback_error:
                        rollback_failures.append(
                            {
                                "external_system": "ise",
                                "error_type": type(rollback_error).__name__,
                            }
                        )
                final = "rollback_failed" if rollback_failures else "rolled_back"
                updated = self.store.transition_run(
                    run_id,
                    final,
                    self.actor,
                    {"rollback_failures": rollback_failures},
                )
                plan_record = self.store.get_plan(str(run["plan_id"]))
                if plan_record.get("reservation_id"):
                    self.store.transition_design_reservation(
                        str(plan_record["reservation_id"]),
                        "quarantined" if rollback_failures else "released",
                        self.actor,
                        verified=not rollback_failures,
                    )
                return {
                    "succeeded": False,
                    "run": updated,
                    "rolled_back": not rollback_failures,
                    "failure_type": type(exc).__name__,
                }
            updated = self.store.transition_run(
                run_id,
                "apply_failed",
                self.actor,
                {"failure_type": type(exc).__name__},
            )
            return {
                "succeeded": False,
                "run": updated,
                "rolled_back": False,
                "failure_type": type(exc).__name__,
            }
        finally:
            for adapter in adapters.values():
                adapter.close()
            if ise_adapter is not None:
                ise_adapter.close()
