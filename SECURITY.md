# Security Policy

## Development status

This repository is an experimental automation foundation. Live device apply is
disabled by default and must remain disabled until the target environment has
passed checkpoint, rollback, failure-injection, authorization, secret-storage,
and hardware acceptance tests.

## Sensitive data

Do not commit or submit in issues:

- Meraki API keys or account keys
- Switch, server, ISE, or hypervisor credentials
- Private SSH keys or certificates containing private keys
- Real organization/network identifiers
- Customer or internal management addresses
- Raw running configuration or device evidence
- `.env`, local intent, inventory, evidence, or database files

Use `secret://` references in intent documents and resolve them only inside the
bounded execution worker. Rotate any credential that is accidentally exposed.

## Reporting

Report security concerns privately to the repository owner. Do not create a
public issue containing exploit details, credentials, customer data, or network
topology.
