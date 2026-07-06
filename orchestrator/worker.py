"""Transactional apply worker with prechecks, checkpoints, gates, and rollback.

The API does not instantiate this worker. Production enablement requires a
separate bounded worker process, secret resolver, queue, and explicit runtime
flag. Unit tests use fake adapters only.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Mapping

from .gates import build_gate_plan, evaluate_gate
from .store import ConflictError, StateStore


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
    ):
        self.store = store
        self.adapter_factory = adapter_factory
        self.secret_resolver = secret_resolver
        self.actor = actor

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
        if artifact.get("blocking_requirements"):
            updated = self.store.transition_run(
                run_id,
                "apply_failed",
                self.actor,
                {"reason": "artifact_has_blocking_requirements"},
            )
            return {"succeeded": False, "run": updated, "rolled_back": False}

        devices = {str(device["id"]): device for device in intent["devices"]}
        adapters: Dict[str, Any] = {}
        checkpoints: Dict[str, str] = {}
        gate_plan = build_gate_plan(intent)
        changed_devices: List[str] = []
        self.store.transition_run(run_id, "apply_running", self.actor)
        try:
            for device_id in sorted(devices):
                adapter = self.adapter_factory(devices[device_id])
                adapter.connect()
                adapters[device_id] = adapter

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
                "underlay",
                "lisp_control_plane",
                "lisp_edges",
                "overlay",
                "border_handoff",
            ]
            for phase_id in ordered_phases:
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

            updated = self.store.transition_run(
                run_id,
                "apply_succeeded",
                self.actor,
                {"changed_devices": sorted(changed_devices)},
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
            if checkpoints:
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
