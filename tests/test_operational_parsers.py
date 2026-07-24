from __future__ import annotations

import unittest

from orchestrator.parsers import (
    verify_bgp_neighbors,
    verify_exact_config_lines,
    verify_isis_neighbors,
    verify_ios_xe_license_level,
    verify_lisp_identity,
    verify_lisp_publishers,
    verify_lisp_sessions,
    verify_msdp_peers,
    verify_nve_peers,
    verify_pim_interfaces,
    verify_role_permission,
    verify_route_prefix,
    verify_sxp_connections,
)


class OperationalParserTests(unittest.TestCase):
    def test_ios_xe_license_requires_advantage_now_and_after_reboot(self):
        compliant = """
Technology-package                                     Technology-package
Current                        Type                       Next reboot
network-advantage             Smart License              network-advantage
dna-advantage                 Subscription Smart License dna-advantage
"""
        result = verify_ios_xe_license_level(compliant)
        self.assertTrue(result.passed)
        self.assertEqual(
            "network-advantage",
            result.observations["next_reboot_network_package"],
        )

        catalyst = compliant.replace("dna-advantage", "catalyst-advantage")
        self.assertTrue(verify_ios_xe_license_level(catalyst).passed)

    def test_ios_xe_license_downgrade_or_missing_row_fails_closed(self):
        baseline = """
network-advantage   Smart License                 network-advantage
dna-advantage       Subscription Smart License    dna-advantage
"""
        rejected = [
            baseline.replace(
                "network-advantage\n", "network-essentials\n", 1
            ),
            baseline.replace(
                "network-advantage   Smart License                 network-advantage",
                "network-essentials  Smart License                 network-advantage",
            ),
            baseline.replace(
                "dna-advantage       Subscription Smart License    dna-advantage",
                "dna-essentials      Subscription Smart License    dna-advantage",
            ),
            baseline.replace(
                "dna-advantage       Subscription Smart License    dna-advantage",
                "dna-advantage       Subscription Smart License    dna-essentials",
            ),
            "Technology-package Current Type Next reboot",
            baseline + baseline,
            """
network-advantage   Smart License                 network-advantage-extra
dna-advantage       Subscription Smart License    dna-advantage
""",
        ]
        for output in rejected:
            with self.subTest(output=output):
                self.assertFalse(verify_ios_xe_license_level(output).passed)

        self.assertFalse(
            verify_ios_xe_license_level(
                baseline,
                allowed_subscription_packages=[],
            ).passed
        )

    def test_lisp_up_down_header_does_not_create_false_positive(self):
        output = """
Sessions for VRF default, total: 1, established: 0
Peer               State      Up/Down        In/Out    Users
10.255.255.1:4342  Down       never           0/0      4
"""
        result = verify_lisp_sessions(output)
        self.assertFalse(result.passed)
        self.assertEqual(0, result.observations["established"])

    def test_explicit_established_lisp_session_passes(self):
        output = """
Sessions for VRF default, total: 1, established: 1
Peer               State      Up/Down        In/Out    Users
10.255.255.1:4342  Up         00:01:10        4/4      10
"""
        result = verify_lisp_sessions(output)
        self.assertTrue(result.passed)
        self.assertEqual("up", result.observations["peers"][0]["state"])

    def test_missing_lisp_counter_fails_closed(self):
        result = verify_lisp_sessions("LISP output unavailable")
        self.assertFalse(result.passed)
        self.assertIsNone(result.observations["established"])

    def test_all_expected_lisp_publishers_must_be_established(self):
        output = """
Publisher                 State            Session             PubSub State
192.0.2.10                Reachable        Up                  Established
192.0.2.11                Reachable        Up                  Established
"""
        result = verify_lisp_publishers(output, ["192.0.2.10", "192.0.2.11"])
        self.assertTrue(result.passed)
        self.assertEqual(
            ["192.0.2.10", "192.0.2.11"],
            result.observations["established_publishers"],
        )

    def test_lisp_publisher_header_or_partial_state_fails_closed(self):
        output = """
Publisher                 State            Session             PubSub State
192.0.2.10                Reachable        Up                  Established
192.0.2.11                Reachable        Down                Disconnected
"""
        result = verify_lisp_publishers(output, ["192.0.2.10", "192.0.2.11"])
        self.assertFalse(result.passed)
        self.assertEqual(
            ["192.0.2.11"], result.observations["missing_publishers"]
        )
        self.assertFalse(
            verify_lisp_publishers(
                "Publisher State Session PubSub State", ["192.0.2.10"]
            ).passed
        )

    def test_lisp_identity_requires_exact_domain_and_multihoming_values(self):
        output = """
router lisp
 domain-id 424242
 multihoming-id 4242
 service ipv4
"""
        self.assertTrue(verify_lisp_identity(output, 424242, 4242).passed)
        self.assertFalse(verify_lisp_identity(output, 424243, 4242).passed)
        self.assertFalse(verify_lisp_identity(output, 424242, None).passed)
        self.assertTrue(
            verify_lisp_identity(
                "router lisp\n domain-id 424242\n service ipv4", 424242, None
            ).passed
        )

    def test_exact_config_lines_require_one_exact_occurrence(self):
        expected = [
            "ip multicast-routing vrf MEDIA_VN",
            "ip pim vrf MEDIA_VN register-source Loopback5003",
        ]
        output = "\n".join(expected)
        self.assertTrue(verify_exact_config_lines(output, expected).passed)
        self.assertFalse(
            verify_exact_config_lines(output + "\n" + expected[0], expected).passed
        )
        self.assertFalse(
            verify_exact_config_lines("multicast-routing vrf MEDIA_VN", expected).passed
        )

    def test_pim_interfaces_require_explicit_sparse_mode_rows(self):
        expected = ["Loopback5003", "LISP0.5003", "Vlan123"]
        output = """
Address          Interface       Ver/Mode  Nbr  Query
10.1.1.1         Loopback5003    v2/S      0    30
10.1.1.1         LISP0.5003      v2/S      0    30
10.1.1.2         Vlan123         v2/S      0    30
"""
        self.assertTrue(verify_pim_interfaces(output, expected).passed)
        self.assertFalse(
            verify_pim_interfaces(output.replace("Vlan123", "Vlan124"), expected).passed
        )
        self.assertFalse(
            verify_pim_interfaces("Interface Ver/Mode Nbr Query", expected).passed
        )
        for rejected_mode in ("v2/SD", "v2/D"):
            with self.subTest(mode=rejected_mode):
                self.assertFalse(
                    verify_pim_interfaces(
                        "10.1.1.1 Loopback5003 {} 0 30".format(rejected_mode),
                        ["Loopback5003"],
                    ).passed
                )

    def test_msdp_requires_each_exact_peer_to_be_established(self):
        output = """
MSDP Peer 10.242.255.2 (?), AS 0, state: established
  Connection source: Loopback0
MSDP Peer 10.242.255.3 (?), AS 0, state: inactive
  Connection source: Loopback0
"""
        result = verify_msdp_peers(output, ["10.242.255.2", "10.242.255.3"])
        self.assertFalse(result.passed)
        self.assertEqual(["10.242.255.3"], result.observations["missing_peers"])
        self.assertTrue(verify_msdp_peers(output, ["10.242.255.2"]).passed)
        self.assertFalse(
            verify_msdp_peers("MSDP Peer State", ["10.242.255.2"]).passed
        )

    def test_sxp_requires_exact_peer_source_speaker_and_on_state(self):
        output = """
SXP                     : Enabled
----------------------------------------------
Peer IP                 : 203.0.113.20
Source IP               : 10.241.0.0
Conn status             : On
Connection mode         : SXP Speaker
"""
        expected = [{"peer": "203.0.113.20", "source_ip": "10.241.0.0"}]
        self.assertTrue(verify_sxp_connections(output, expected).passed)
        self.assertFalse(
            verify_sxp_connections(
                output,
                [{"peer": "203.0.113.21", "source_ip": "10.241.0.0"}],
            ).passed
        )
        self.assertFalse(verify_sxp_connections("Peer IP Conn status", expected).passed)
        extra = output + """
----------------------------------------------
Peer IP                 : 203.0.113.22
Source IP               : 10.241.0.0
Conn status             : On
Connection mode         : SXP Speaker
"""
        self.assertFalse(verify_sxp_connections(extra, expected).passed)

    def test_role_permission_requires_exact_pair_and_single_sgacl(self):
        output = """
IPv4 Role-based permissions from group 1000:Employees to group 1003:Shared-Services:
  SDA-SGACL-C6B06C63114D
"""
        self.assertTrue(
            verify_role_permission(
                output, 1000, 1003, "SDA-SGACL-C6B06C63114D"
            ).passed
        )
        self.assertFalse(
            verify_role_permission(
                output, 1001, 1003, "SDA-SGACL-C6B06C63114D"
            ).passed
        )
        self.assertFalse(
            verify_role_permission(
                output + "  SDA-SGACL-C6B06C63114D\n",
                1000,
                1003,
                "SDA-SGACL-C6B06C63114D",
            ).passed
        )
        unrelated_block = """
IPv4 Role-based permissions from group 1000:Employees to group 1003:Shared-Services:
  OTHER-SGACL
IPv4 Role-based permissions from group 1001:Guests to group 1003:Shared-Services:
  SDA-SGACL-C6B06C63114D
"""
        self.assertFalse(
            verify_role_permission(
                unrelated_block, 1000, 1003, "SDA-SGACL-C6B06C63114D"
            ).passed
        )

    def test_isis_table_header_without_neighbor_fails(self):
        output = "System Id Type Interface IP Address State Holdtime Circuit Id"
        self.assertFalse(verify_isis_neighbors(output).passed)

    def test_isis_up_neighbor_row_passes(self):
        output = """
System Id       Type Interface     IP Address      State Holdtime Circuit Id
SJC23-EDGE-01   L2   Twe1/0/2      10.255.0.1      UP    24       0A
"""
        result = verify_isis_neighbors(output)
        self.assertTrue(result.passed)
        self.assertEqual(1, result.observations["up_neighbor_count"])

    def test_empty_nve_peer_table_fails(self):
        output = """
'M' - MAC entry download flag  'A' - Adjacency download flag
Interface  VNI      Type Peer-IP          RMAC/Num_RTs   eVNI     state flags UP time
"""
        self.assertFalse(verify_nve_peers(output).passed)

    def test_explicit_nve_peer_row_passes(self):
        output = """
Interface  VNI      Type Peer-IP          RMAC/Num_RTs   eVNI     state flags UP time
nve1       8100     L2CP 10.255.255.2     2              8100     UP    A/M   00:12:00
"""
        result = verify_nve_peers(output)
        self.assertTrue(result.passed)
        self.assertEqual(1, result.observations["up_peer_count"])

    def test_bgp_requires_numeric_established_state_for_every_peer(self):
        output = """
Neighbor        V    AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd
198.51.100.1    4 65100      12      14      3   0    0 00:10:00 8
198.51.100.3    4 65100       0       0      3   0    0 never    Active
"""
        result = verify_bgp_neighbors(output, ["198.51.100.1", "198.51.100.3"])
        self.assertFalse(result.passed)
        self.assertEqual(["198.51.100.3"], result.observations["missing_neighbors"])

    def test_all_expected_bgp_neighbors_pass(self):
        output = "198.51.100.1 4 65100 12 14 3 0 0 00:10:00 8"
        self.assertTrue(verify_bgp_neighbors(output, ["198.51.100.1"]).passed)

    def test_exact_route_prefix_evidence_is_required(self):
        output = "Routing entry for 203.0.113.0/26\n  Known via static"
        self.assertTrue(verify_route_prefix(output, "203.0.113.0/26").passed)
        self.assertFalse(verify_route_prefix(output, "203.0.113.64/26").passed)
        self.assertFalse(
            verify_route_prefix("% Network not in table", "203.0.113.0/26").passed
        )


if __name__ == "__main__":
    unittest.main()
