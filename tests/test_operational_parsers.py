from __future__ import annotations

import unittest

from orchestrator.parsers import (
    verify_bgp_neighbors,
    verify_isis_neighbors,
    verify_lisp_publishers,
    verify_lisp_sessions,
    verify_nve_peers,
    verify_route_prefix,
)


class OperationalParserTests(unittest.TestCase):
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
