# COP29-derived sanitized acceptance fixture

This fixture converts reusable scale and data-quality lessons from the private
COP29 reference package into synthetic, publishable acceptance inputs. It does
not reproduce customer names, hostnames, serial numbers, management addresses,
credentials, routing values, or private configuration.

## Scope proved in this phase

- One large fabric site represented by an area, two buildings, four floors,
  and four fabric zones.
- Two combined border/control-plane nodes, four fabric edges, and two routed
  underlay uplinks per edge.
- Six virtual networks and deterministic endpoint, VLAN, L2/L3 instance,
  route distinguisher, route target, loopback, and underlay allocation.
- Twenty-four BGP handoffs: every virtual network across a complete two-border,
  two-fusion adjacency matrix, using synthetic `/30` allocation policy and
  usable host addresses.
- LISP Pub/Sub publisher/subscriber planning, native multicast with two
  Anycast-RP nodes, deterministic shared-service route leaks, and hybrid
  ISE/SXP policy-plane intent.
- Dynamically reserved SGTs and directional policy contracts with strict
  reference and uniqueness validation.
- Production redundancy validation, deterministic repeatability, semantic
  intent validation, and body-size headroom under the current 1 MiB API limit.
- Rejection of an endpoint gateway outside its allocated prefix and rejection
  of duplicate route distinguishers.

The execution and Dashboard inventory planes use RFC 5737 documentation
ranges. Device credentials and the LISP authentication key are references only;
the fixture contains no secret values.

## Deliberate boundaries

This is an acceptance fixture for the capabilities implemented today, not a
claim of full COP29 or Cisco SD-Access feature parity. Fusion, shared services,
multicast, Pub/Sub, and ISE/SXP are now explicit planning contracts. Their
release-specific apply renderers remain fail-closed pending hardware/API,
failure-injection, and rollback acceptance. Wireless and service-node
provisioning remain outside this fixture.

The private COP29 source remains local reference material and must never be
copied into this public repository.
