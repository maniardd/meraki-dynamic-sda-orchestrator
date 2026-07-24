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


def verify_lisp_identity(
    output: str, expected_domain_id: int, expected_multihoming_id: int | None
) -> GateResult:
    """Require exact router-LISP domain and topology identity configuration."""

    domain_ids = [
        int(match.group(1))
        for match in re.finditer(
            r"^\s*domain-id\s+(\d+)\s*$",
            output,
            flags=re.IGNORECASE | re.MULTILINE,
        )
    ]
    multihoming_ids = [
        int(match.group(1))
        for match in re.finditer(
            r"^\s*multihoming-id\s+(\d+)\s*$",
            output,
            flags=re.IGNORECASE | re.MULTILINE,
        )
    ]
    expected_multihoming = (
        [] if expected_multihoming_id is None else [int(expected_multihoming_id)]
    )
    passed = (
        domain_ids == [int(expected_domain_id)]
        and multihoming_ids == expected_multihoming
    )
    reason = (
        "LISP domain and multihoming identity match intent"
        if passed
        else "LISP domain or multihoming identity does not match intent"
    )
    return GateResult(
        passed,
        reason,
        {
            "expected_domain_id": int(expected_domain_id),
            "observed_domain_ids": domain_ids,
            "expected_multihoming_id": expected_multihoming_id,
            "observed_multihoming_ids": multihoming_ids,
        },
    )


def verify_exact_config_lines(output: str, expected_lines: List[str]) -> GateResult:
    """Require every expected configuration line exactly once."""

    observed = [line.strip() for line in output.splitlines() if line.strip()]
    expected = [str(line).strip() for line in expected_lines]
    missing = [line for line in expected if observed.count(line) != 1]
    passed = not missing
    reason = (
        "Every expected configuration line is present exactly once"
        if passed
        else "Expected configuration lines are missing or duplicated"
    )
    return GateResult(
        passed,
        reason,
        {"expected_lines": expected, "observed_lines": observed, "failed_lines": missing},
    )


def verify_config_lines_absent(output: str, forbidden_lines: List[str]) -> GateResult:
    """Require every exact workflow-owned configuration line to be absent."""

    observed = [line.strip() for line in output.splitlines() if line.strip()]
    forbidden = [str(line).strip() for line in forbidden_lines]
    present = [line for line in forbidden if observed.count(line) != 0]
    passed = not present
    reason = (
        "Every stale workflow-owned configuration line is absent"
        if passed
        else "One or more stale workflow-owned configuration lines remain"
    )
    return GateResult(
        passed,
        reason,
        {
            "forbidden_lines": forbidden,
            "observed_lines": observed,
            "present_lines": present,
        },
    )


def verify_pim_interfaces(output: str, expected_interfaces: List[str]) -> GateResult:
    """Require an explicit sparse-mode PIM row for every intended interface."""

    expected = sorted(set(str(item) for item in expected_interfaces))
    sparse_interfaces = set()
    rows: List[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        interface = fields[1] if re.fullmatch(IPV4_PATTERN, fields[0]) else fields[0]
        if interface not in expected:
            continue
        mode = re.search(r"\bv\d+/([A-Z]+)\b", line, flags=re.IGNORECASE)
        if mode is None or mode.group(1).upper() not in {"S", "SM"}:
            continue
        sparse_interfaces.add(interface)
        rows.append(line)
    missing = sorted(set(expected) - sparse_interfaces)
    passed = not missing
    reason = (
        "Every expected PIM interface is present in sparse mode"
        if passed
        else "One or more expected PIM sparse-mode interfaces are absent"
    )
    return GateResult(
        passed,
        reason,
        {
            "expected_interfaces": expected,
            "sparse_interfaces": sorted(sparse_interfaces),
            "missing_interfaces": missing,
            "matched_rows": rows,
        },
    )


def verify_msdp_peers(output: str, expected_peers: List[str]) -> GateResult:
    """Require an explicit established state block for every expected MSDP peer."""

    expected = sorted(set(str(item) for item in expected_peers))
    established: List[str] = []
    for peer in expected:
        block = re.search(
            r"(?ims)^\s*MSDP\s+Peer\s+{}\b(?:(?!^\s*MSDP\s+Peer\s+).)*?"
            r"\bstate\s*:\s*(?:established|up)\b".format(re.escape(peer)),
            output,
        )
        if block:
            established.append(peer)
    missing = sorted(set(expected) - set(established))
    return GateResult(
        not missing,
        (
            "Every expected MSDP peer is established"
            if not missing
            else "One or more expected MSDP peers are not established"
        ),
        {
            "expected_peers": expected,
            "established_peers": established,
            "missing_peers": missing,
        },
    )


def verify_sxp_connections(
    output: str, expected_connections: List[Mapping[str, str]]
) -> GateResult:
    """Require each intended peer/source tuple to be explicitly On as speaker."""

    observed: List[Dict[str, str]] = []
    for match in re.finditer(
        r"(?ims)^\s*Peer\s+IP\s*:\s*(?P<peer>\d+\.\d+\.\d+\.\d+)\s*$"
        r"(?P<body>.*?)(?=^\s*-{5,}\s*$|^\s*Peer\s+IP\s*:|\Z)",
        output,
    ):
        body = match.group("body")
        source_match = re.search(
            r"(?im)^\s*Source\s+IP\s*:\s*(\d+\.\d+\.\d+\.\d+)\s*$",
            body,
        )
        status_match = re.search(
            r"(?im)^\s*Conn\s+status\s*:\s*([^\r\n]+)$", body
        )
        mode_match = re.search(
            r"(?im)^\s*(?:Connection|Local)\s+mode\s*:\s*([^\r\n]+)$",
            body,
        )
        observed.append(
            {
                "peer": match.group("peer"),
                "source_ip": source_match.group(1) if source_match else "",
                "status": status_match.group(1).strip() if status_match else "",
                "mode": mode_match.group(1).strip() if mode_match else "",
            }
        )
    missing = []
    expected_pairs = {
        (str(item["peer"]), str(item["source_ip"]))
        for item in expected_connections
    }
    observed_pairs = {
        (str(item["peer"]), str(item["source_ip"])) for item in observed
    }
    for expected in expected_connections:
        peer = str(expected["peer"])
        source_ip = str(expected["source_ip"])
        if not any(
            item["peer"] == peer
            and item["source_ip"] == source_ip
            and re.fullmatch(r"On(?:\s*\(Speaker\))?", item["status"], re.IGNORECASE)
            and "speaker" in item["mode"].lower()
            for item in observed
        ):
            missing.append({"peer": peer, "source_ip": source_ip})
    unexpected = [
        {"peer": peer, "source_ip": source_ip}
        for peer, source_ip in sorted(observed_pairs - expected_pairs)
    ]
    duplicates = len(observed) != len(observed_pairs)
    passed = not missing and not unexpected and not duplicates
    return GateResult(
        passed,
        (
            "The exact intended SXP speaker connection set is On"
            if passed
            else "The SXP connection set or operational state does not match intent"
        ),
        {
            "expected": expected_connections,
            "observed": observed,
            "missing": missing,
            "unexpected": unexpected,
            "duplicates": duplicates,
        },
    )


def verify_role_permission(
    output: str, source_tag: int, destination_tag: int, sgacl_name: str
) -> GateResult:
    """Require an exact source/destination policy block containing the SGACL."""

    header_pattern = (
        r"^\s*(?:IPv4\s+)?Role-based permissions from group\s+{}(?:\:[^\s]+)?"
        r"\s+to group\s+{}(?:\:[^\s]+)?\s*:\s*$"
    ).format(
            int(source_tag), int(destination_tag)
        )
    headers = list(re.finditer(header_pattern, output, flags=re.IGNORECASE | re.MULTILINE))
    body = ""
    if len(headers) == 1:
        body = output[headers[0].end() :]
        next_header = re.search(
            r"(?im)^\s*(?:IPv4\s+)?Role-based permissions from group\s+",
            body,
        )
        if next_header:
            body = body[: next_header.start()]
    acl_matches = re.findall(
        r"(?m)^\s*{}\s*$".format(re.escape(str(sgacl_name))), body
    )
    passed = len(headers) == 1 and len(acl_matches) == 1
    return GateResult(
        passed,
        (
            "Role-based permission and SGACL match intent"
            if passed
            else "Role-based permission or SGACL does not match intent"
        ),
        {
            "source_tag": int(source_tag),
            "destination_tag": int(destination_tag),
            "sgacl_name": str(sgacl_name),
            "header_occurrences": len(headers),
            "sgacl_occurrences": len(acl_matches),
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


def verify_ios_xe_license_level(
    output: str,
    required_network_package: str = "network-advantage",
    allowed_subscription_packages: List[str] | None = None,
) -> GateResult:
    """Require running and next-reboot SDA license packages to remain Advantage."""

    configured_subscriptions = (
        ["catalyst-advantage", "dna-advantage"]
        if allowed_subscription_packages is None
        else allowed_subscription_packages
    )
    allowed_subscriptions = sorted(
        {
            str(item).strip().lower()
            for item in configured_subscriptions
            if str(item).strip()
        }
    )
    required_network = str(required_network_package).strip().lower()

    network_matches = re.findall(
        r"^\s*(network-(?:advantage|essentials))\s+"
        r".*?\s+(network-(?:advantage|essentials))\s*$",
        output,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    subscription_matches = re.findall(
        r"^\s*((?:catalyst|dna)-(?:advantage|essentials))\s+"
        r".*?\s+((?:catalyst|dna)-(?:advantage|essentials))\s*$",
        output,
        flags=re.IGNORECASE | re.MULTILINE,
    )

    current_network, next_network = (
        tuple(value.lower() for value in network_matches[0])
        if len(network_matches) == 1
        else (None, None)
    )
    current_subscription, next_subscription = (
        tuple(value.lower() for value in subscription_matches[0])
        if len(subscription_matches) == 1
        else (None, None)
    )

    passed = (
        len(network_matches) == 1
        and len(subscription_matches) == 1
        and bool(allowed_subscriptions)
        and current_network == required_network
        and next_network == required_network
        and current_subscription in allowed_subscriptions
        and next_subscription in allowed_subscriptions
    )
    reason = (
        "Running and next-reboot IOS XE license packages satisfy SDA policy"
        if passed
        else "IOS XE running or next-reboot license package does not satisfy SDA policy"
    )
    return GateResult(
        passed,
        reason,
        {
            "required_network_package": required_network,
            "allowed_subscription_packages": allowed_subscriptions,
            "network_row_count": len(network_matches),
            "subscription_row_count": len(subscription_matches),
            "current_network_package": current_network,
            "next_reboot_network_package": next_network,
            "current_subscription_package": current_subscription,
            "next_reboot_subscription_package": next_subscription,
        },
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
