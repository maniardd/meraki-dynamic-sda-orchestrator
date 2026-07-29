# SJC23 POC guided Meraki intake

This native-Meraki prompt flow is for the two-switch isolated SJC23 POC. It
produces a zero-write plan only and does not enable Apply.

## Native prompt fields

Create a disabled child workflow named **SDA Fabric - SJC23 POC Guided Intake**
with one Create Prompt task. Operators never paste JSON.

| Label | Variable | Type | Required | POC value |
| --- | --- | --- | --- | --- |
| Fabric name | `fabricName` | Text | Yes | 3–128 letters/numbers/spaces/`._-` |
| Change reference | `changeReference` | Text | Yes | `SJC23-POC-001` |
| Corporate capacity | `corporateUsers` | Dropdown | Yes | `150` (range 1–200) |
| Guest capacity | `guestUsers` | Dropdown | Yes | `150` (range 1–200) |
| Corporate attachment | `corporateAttachment` | Dropdown | Yes | `corporate_laptop` — Edge Gi1/0/10 |
| Guest attachment | `guestAttachment` | Dropdown | Yes | `guest_laptop` — Edge Gi1/0/11 |
| DHCP lease | `dhcpLeaseMinutes` | Dropdown | Yes | `60` (range 30–1440) |
| DNS profile | `dnsProfile` | Dropdown | Yes | `public_google` — 8.8.8.8 / 8.8.4.4 |

After the prompt, add a Planner-target `POST` HTTP Request to the fixed
relative URL `/v1/workflow-actions/poc-guided-plan`. Build the body with native
variable bindings, not quoted string interpolation:

```json
{
  "form_values": {
    "fabric_name": "<fabricName>",
    "change_reference": "<changeReference>",
    "corporate_users": "<corporateUsers>",
    "guest_users": "<guestUsers>",
    "corporate_attachment": "<corporateAttachment>",
    "guest_attachment": "<guestAttachment>",
    "dhcp_lease_minutes": "<dhcpLeaseMinutes>",
    "dns_profile": "<dnsProfile>"
  },
  "idempotency_key": "<workflow-instance-id>"
}
```

The server, not the operator, supplies the inventory, secret references,
underlay, loopbacks, VLANs, VNIs, DHCP helper, and DHCP configuration. With the
reviewed POC guardrail profile, Corporate derives `10.30.100.0/24` / VLAN 100
and Guest derives `10.30.200.0/24` / VLAN 200. They remain separate VRFs;
cross-VN communication is neither requested nor enabled here.

This endpoint refuses to run unless policy version `1.0-sjc23-poc` is active.
It is not a generic production intake endpoint.
