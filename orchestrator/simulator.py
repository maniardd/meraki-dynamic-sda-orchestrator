"""No-side-effect run processor used before any device adapter is enabled."""

from __future__ import annotations

from typing import Any, Dict, Mapping

from .store import ConflictError, StateStore


def process_dry_run(
    store: StateStore,
    run_id: str,
    artifact: Mapping[str, Any],
    actor: str,
) -> Dict[str, Any]:
    run = store.get_run(run_id)
    if run["mode"] != "dry_run":
        raise ConflictError("Simulator accepts dry_run records only")
    if run["status"] != "dry_run_queued":
        raise ConflictError("Dry run is not queued")

    store.transition_run(run_id, "dry_run_running", actor)
    command_blocks = 0
    command_count = 0
    phase_count = 0
    try:
        for device_id, device in artifact["devices"].items():
            for phase in device["phases"]:
                phase_count += 1
                blocks = phase["blocks"]
                command_blocks += len(blocks)
                command_count += sum(len(block["commands"]) for block in blocks)
                store.add_evidence(
                    run_id=run_id,
                    phase_id=str(phase["phase_id"]),
                    device_id=str(device_id),
                    evidence_type="rendered_configuration",
                    payload={
                        "artifact_hash": artifact["artifact_hash"],
                        "device_id": device_id,
                        "phase_id": phase["phase_id"],
                        "block_hashes": [block["command_hash"] for block in blocks],
                        "block_count": len(blocks),
                        "command_count": sum(len(block["commands"]) for block in blocks),
                        "contains_secret_values": False,
                    },
                    actor=actor,
                )
        blockers = list(artifact.get("blocking_requirements", []))
        summary = {
            "artifact_hash": artifact["artifact_hash"],
            "device_count": len(artifact["devices"]),
            "phase_count": phase_count,
            "command_block_count": command_blocks,
            "command_count": command_count,
            "blocking_requirements": blockers,
        }
        store.add_evidence(
            run_id=run_id,
            phase_id="dry_run_summary",
            evidence_type="simulation_summary",
            payload=summary,
            actor=actor,
        )
        final_status = "dry_run_blocked" if blockers else "dry_run_succeeded"
        updated = store.transition_run(run_id, final_status, actor, summary)
        return {"run": updated, "summary": summary, "evidence": store.run_evidence(run_id)}
    except Exception as exc:
        store.transition_run(
            run_id,
            "dry_run_failed",
            actor,
            {"error_type": type(exc).__name__},
        )
        raise
