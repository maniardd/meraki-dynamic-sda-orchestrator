"""Exact operational gates for fabric control-plane and data-plane evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List


IPV4_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}"


@dataclass(frozen=True)
class GateResult:
    passed: bool
    reason: str
    observations: Dict[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "reason": self.reason,
            "observations": self.observations,
        }


def verify_isis_neighbors(output: str, minimum_up: int = 1) -> GateResult:
    """Require actual IS-IS neighbor rows whose state column is UP."""
    up_rows: List[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith("system id"):
            continue
        fields = line.split()
        if len(fields) < 6:
            continue
        # Expected IOS XE columns:
        # System-Id Type Interface IP-Address State Holdtime Circuit-Id
        if re.fullmatch(IPV4_PATTERN, fields[3]) and fields[4].upper() == "UP":
            up_rows.append(line)

    passed = len(up_rows) >= minimum_up
    reason = (
        f"Found {len(up_rows)} UP IS-IS neighbor(s); required {minimum_up}"
        if passed
        else f"Expected at least {minimum_up} UP IS-IS neighbor(s), found {len(up_rows)}"
    )
    return GateResult(passed, reason, {"up_neighbor_count": len(up_rows), "rows": up_rows})


def verify_lisp_sessions(output: str, minimum_established: int = 1) -> GateResult:
    """Parse the explicit established counter; never match the Up/Down header."""
    match = re.search(r"\bestablished\s*:\s*(\d+)\b", output, flags=re.IGNORECASE)
    if not match:
        return GateResult(
            False,
            "LISP established-session counter was not found",
            {"established": None},
        )

    established = int(match.group(1))
    peer_states: List[Dict[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        peer = re.match(
            rf"^(?P<peer>{IPV4_PATTERN}:\d+)\s+(?P<state>Up|Down)\b",
            line,
            flags=re.IGNORECASE,
        )
        if peer:
            peer_states.append(
                {
                    "peer": peer.group("peer"),
                    "state": peer.group("state").lower(),
                }
            )

    passed = established >= minimum_established
    reason = (
        f"Found {established} established LISP session(s); required {minimum_established}"
        if passed
        else f"Expected at least {minimum_established} established LISP session(s), found {established}"
    )
    return GateResult(
        passed,
        reason,
        {"established": established, "peers": peer_states},
    )


def verify_lisp_publishers(output: str, expected_publishers: List[str]) -> GateResult:
    """Require every expected Pub/Sub publisher to be fully established."""

    publisher_rows: Dict[str, Dict[str, str]] = {}
    for raw_line in output.splitlines():
        match = re.match(
            rf"^\s*(?P<publisher>{IPV4_PATTERN})\s+"
            r"(?P<state>\S+)\s+(?P<session>\S+)\s+(?P<pubsub>\S+)\s*$",
            raw_line,
            flags=re.IGNORECASE,
        )
        if not match:
            continue
        publisher_rows[match.group("publisher")] = {
            "state": match.group("state").lower(),
            "session": match.group("session").lower(),
            "pubsub_state": match.group("pubsub").lower(),
        }

    established = sorted(
        publisher
        for publisher, row in publisher_rows.items()
        if row == {
            "state": "reachable",
            "session": "up",
            "pubsub_state": "established",
        }
    )
    expected = sorted(set(str(item) for item in expected_publishers))
    missing = sorted(set(expected) - set(established))
    passed = bool(expected) and not missing
    reason = (
        "All {} expected LISP publisher(s) are established".format(len(expected))
        if passed
        else "Missing established LISP publishers: {}".format(
            ", ".join(missing) or "none specified"
        )
    )
    return GateResult(
        passed,
        reason,
        {
            "expected_publishers": expected,
            "established_publishers": established,
            "missing_publishers": missing,
            "publisher_rows": publisher_rows,
        },
    )


def verify_nve_peers(output: str, minimum_up: int = 1) -> GateResult:
    """Require data rows containing both a peer IP and an explicit UP state."""
    up_rows: List[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith(("interface", "'m'", "'4'")):
            continue
        if not re.search(IPV4_PATTERN, line):
            continue
        if re.search(r"\bup\b", line, flags=re.IGNORECASE):
            up_rows.append(line)

    passed = len(up_rows) >= minimum_up
    reason = (
        f"Found {len(up_rows)} UP NVE peer(s); required {minimum_up}"
        if passed
        else f"Expected at least {minimum_up} UP NVE peer(s), found {len(up_rows)}"
    )
    return GateResult(passed, reason, {"up_peer_count": len(up_rows), "rows": up_rows})


def verify_bgp_neighbors(output: str, expected_neighbors: List[str]) -> GateResult:
    """Require every expected BGP peer to have a numeric prefix count."""
    established: Dict[str, int] = {}
    for raw_line in output.splitlines():
        fields = raw_line.strip().split()
        if len(fields) < 3 or not re.fullmatch(IPV4_PATTERN, fields[0]):
            continue
        # IOS XE summary uses a numeric PfxRcd value in the final column when
        # established; Idle, Active, Connect, and similar states are strings.
        if fields[-1].isdigit():
            established[fields[0]] = int(fields[-1])
    missing = sorted(set(expected_neighbors) - set(established))
    passed = bool(expected_neighbors) and not missing
    reason = (
        "All {} expected BGP neighbor(s) are established".format(len(expected_neighbors))
        if passed
        else "Missing established BGP neighbors: {}".format(
            ", ".join(missing) or "none specified"
        )
    )
    return GateResult(
        passed,
        reason,
        {
            "expected_neighbors": sorted(expected_neighbors),
            "established_neighbors": established,
            "missing_neighbors": missing,
        },
    )


def verify_ios_xe_version(output: str, expected_version: str) -> GateResult:
    """Require the running IOS XE version to match the intent baseline exactly."""
    match = re.search(
        r"Cisco IOS XE Software,\s*Version\s+([A-Za-z0-9()._-]+)",
        output,
        flags=re.IGNORECASE,
    )
    if not match:
        match = re.search(r"\bVersion\s+([0-9]+(?:\.[0-9A-Za-z()-]+){2,})", output)
    observed = match.group(1) if match else None
    passed = observed is not None and observed.lower() == expected_version.lower()
    reason = (
        "IOS XE version matches {}".format(expected_version)
        if passed
        else "Expected IOS XE {}, observed {}".format(expected_version, observed or "unavailable")
    )
    return GateResult(
        passed,
        reason,
        {"expected_version": expected_version, "observed_version": observed},
    )


def verify_route_prefix(output: str, expected_prefix: str) -> GateResult:
    """Require the exact IOS XE `Routing entry for` prefix evidence."""

    expected = str(expected_prefix)
    observed = [
        match.group(1)
        for match in re.finditer(
            rf"^\s*Routing entry for\s+({IPV4_PATTERN}/\d{{1,2}})\s*$",
            output,
            flags=re.IGNORECASE | re.MULTILINE,
        )
    ]
    passed = expected in observed and "% Network not in table" not in output
    reason = (
        "Route {} is present".format(expected)
        if passed
        else "Expected route {} was not present".format(expected)
    )
    return GateResult(
        passed,
        reason,
        {"expected_prefix": expected, "observed_prefixes": sorted(set(observed))},
    )
