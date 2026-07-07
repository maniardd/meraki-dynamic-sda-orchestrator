# LISP Pub/Sub renderer and acceptance boundary

## Design basis

The renderer follows Cisco's [Software-Defined Access Solution Design
Guide](https://www.cisco.com/c/en/us/td/docs/solutions/CVD/Campus/cisco-sda-design-guide.html),
which recommends LISP Pub/Sub for new SD-Access deployments, and the IOS XE
[LISP VXLAN border-node configuration
guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/lisp_vxlan/b-179-lisp-vxlan-fabric-cg/configure-border-node-lisp-vxlan.html).
The operational gate uses the publisher command documented in the IOS XE
17.12 [Cisco SD-Access command
reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/command_reference/b_1712_9300_cr/cisco_sd_access_commands.html).

This is an independently implemented automation contract. It does not claim
to reproduce Catalyst Center internals.

## Rendered contract

For IOS XE 17.12-style LISP Pub/Sub, every approved border subscriber imports
every control-plane publisher by its fabric Loopback0 address. The renderer
emits a deterministic global IPv4 LISP service block containing:

- VXLAN encapsulation and publication map-cache import;
- one `import publication publisher`, map-resolver, and secret-referenced
  map-server relationship per approved publisher;
- ETR, publication route export, administrative distance 250, PETR, and the
  subscriber's own Loopback0 as PITR;
- SGT propagation only when a policy plane is enabled; and
- map-server/map-resolver roles only when the subscriber is also an approved
  control-plane node.

The site authentication value remains a `secret://` placeholder in artifacts
and is resolved only inside the separately enabled worker. Publisher and
subscriber order is deterministic. No customer configuration or encrypted
device secret is copied from the reference configurations.

## Operational and rollback gates

After the overlay instance IDs are configured, every border and every L3
instance is checked with:

`show lisp instance-id <iid> ipv4 publisher config-propagation`

The gate passes only when every expected publisher has an exact data row with
`Reachable`, `Up`, and `Established` state. Headers, partial rows, disconnected
publishers, and missing publishers fail closed. A worker failure-injection
test raises inside the Pub/Sub subscriber block and proves checkpoint rollback
and allocation release.

## Hardware acceptance still required

The renderer reports `lisp_pubsub.hardware_acceptance_pending`, so production
apply remains impossible. Clear that blocker only after the target IOS XE
release and topology pass all of the following:

1. CLI parser acceptance on every supported border platform and release.
2. Two publishers and two subscribers establish for every intended IID.
3. Publisher restart and control-plane-node loss retain deterministic
   convergence and forwarding.
4. A rejected or interrupted configuration is restored from a verified device
   checkpoint.
5. Removal of a formerly approved publisher is reconciled without disturbing
   unrelated LISP configuration.
6. Evidence is captured by the production worker and tied to the immutable
   plan, artifact, approval, and change record.

The current SJC23 POC has one combined border/control-plane node and one edge,
so it can prove syntax and single-publisher behavior but cannot satisfy the
redundant production acceptance case by itself.
