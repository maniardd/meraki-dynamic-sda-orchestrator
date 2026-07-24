# IOS XE SDA license precheck

Every active fabric device receives a blocking `precheck.license.<device-id>`
gate before checkpoint creation or configuration. The gate runs `show version`
and requires:

- the running network package to be `network-advantage`;
- the next-reboot network package to remain `network-advantage`; and
- the running and next-reboot subscription packages to be either
  `dna-advantage` or `catalyst-advantage`.

The parser accepts only anchored IOS XE technology-package rows. Missing rows,
headers, Essentials packages, partial matches, and ambiguous output fail
closed.

Cisco's Catalyst 9000 licensing documentation identifies Network Advantage as
the SD-Access base tier and DNA/Catalyst Advantage as the subscription tier
that carries SD-Access capabilities:

- https://www.cisco.com/c/en/us/solutions/collateral/enterprise-networks/software-defined-access/guide-c07-739242.html
- https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst_9000/cat9000-config-available-licenses.html

Changing a configured license level requires configuration and a reload. This
gate performs neither. It only prevents the worker from proceeding when the
running or next-boot state is unsuitable.

The SJC23 border observation from 2026-07-24 fails this gate because its
running package is Network Advantage but its next-reboot package is Network
Essentials. The edge also remains blocked until its subscription tier is
resolved from DNA Essentials to an approved Advantage tier. Apply stays
disabled independently of this gate.
