"""Strict demand-only adapter for the recorded SJC23 POC intake.

The Meraki workflow collects small, understandable form values.  This module
turns that limited input into the canonical requirements document without ever
accepting device credentials, IOS XE commands, IP prefixes, VLANs, or raw
interfaces from an operator.  It is intentionally not a replacement for the
multi-site production intake/portal contract.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import re
from typing import Any, Dict, Mapping

import yaml


ROOT = Path(__file__).resolve().parents[1]
SJC23_POC_PROFILE = ROOT / "examples" / "fabric-requirements.sjc23-poc.yaml"
SJC23_POC_POLICY_VERSION = "1.0-sjc23-poc"

_FABRIC_NAME = re.compile(r"^[A-Za-z0-9_. -]{3,128}$")
_CHANGE_REFERENCE = re.compile(r"^[A-Za-z0-9_.:/-]{3,128}$")
_INTEGER = re.compile(r"^[0-9]{1,3}$")
_ALLOWED_FIELDS = {
    "fabric_name",
    "change_reference",
    "corporate_users",
    "guest_users",
    "corporate_attachment",
    "guest_attachment",
    "dhcp_lease_minutes",
    "dns_profile",
}
_ATTACHMENTS = {
    "corporate_laptop": "corp-laptop",
    "guest_laptop": "guest-laptop",
}
_DNS_PROFILES = {
    "public_google": ["8.8.8.8", "8.8.4.4"],
}
_USER_CAPACITY_OPTIONS = ("1", "50", "100", "150", "200")
_LEASE_MINUTE_OPTIONS = ("30", "60", "120", "240", "480", "1440")

# Meraki native Create Prompt serializes field labels as object keys. Dropdown
# Select values are returned as a single-item array even when multi-select is
# disabled. Keep that transport detail at this narrow boundary; every later
# layer receives the reviewed canonical demand contract only.
_NATIVE_PROMPT_FIELD_MAP = {
    "Fabric name": "fabric_name",
    "Change reference": "change_reference",
    "Corporate users": "corporate_users",
    "Guest users": "guest_users",
    "Corporate attachment": "corporate_attachment",
    "Guest attachment": "guest_attachment",
    "DHCP lease minutes": "dhcp_lease_minutes",
    "DNS profile": "dns_profile",
}
_NATIVE_PROMPT_ARRAY_FIELDS = {
    "Corporate users",
    "Guest users",
    "Corporate attachment",
    "Guest attachment",
    "DHCP lease minutes",
    "DNS profile",
}


class PocIntakeError(ValueError):
    """An untrusted form value cannot be converted into POC demand."""


def _require_sjc23_poc_policy(policy: Mapping[str, Any]) -> None:
    """Ensure the guided helpers cannot be reused against another policy."""

    if policy.get("policy_version") != SJC23_POC_POLICY_VERSION:
        raise PocIntakeError("SJC23 guided POC intake requires the reviewed SJC23 POC guardrail policy")


def sjc23_poc_form_options(policy: Mapping[str, Any]) -> Dict[str, Any]:
    """Return native-prompt choices without exposing fabric implementation data.

    Meraki's native Dropdown Select task takes its option array from a variable
    reference. The fixed arrays here are demand vocabulary only: server-side
    code still owns the reviewed profile, allocation, and every secret.
    """

    _require_sjc23_poc_policy(policy)
    return {
        "succeeded": True,
        "status": "poc_options_ready",
        "policy_version": SJC23_POC_POLICY_VERSION,
        "options": {
            "corporate_users": list(_USER_CAPACITY_OPTIONS),
            "guest_users": list(_USER_CAPACITY_OPTIONS),
            "corporate_attachment": ["corporate_laptop"],
            "guest_attachment": ["guest_laptop"],
            "dhcp_lease_minutes": list(_LEASE_MINUTE_OPTIONS),
            "dns_profile": list(_DNS_PROFILES),
        },
        "contains_secret_values": False,
        "contains_raw_configuration": False,
    }


def _required_text(payload: Mapping[str, Any], field: str, pattern: re.Pattern[str]) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or pattern.fullmatch(value.strip()) is None:
        raise PocIntakeError("{} is invalid".format(field))
    return value.strip()


def _bounded_integer(payload: Mapping[str, Any], field: str, minimum: int, maximum: int) -> int:
    value = payload.get(field)
    text = str(value).strip() if not isinstance(value, bool) else ""
    if _INTEGER.fullmatch(text) is None:
        raise PocIntakeError("{} must be an integer".format(field))
    number = int(text)
    if not minimum <= number <= maximum:
        raise PocIntakeError("{} must be between {} and {}".format(field, minimum, maximum))
    return number


def _canonical_poc_form_values(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Normalize the exact native Prompt Response shape, or canonical API input.

    The public endpoint remains demand-only. A native form can never add a
    topology, addressing, credential, or CLI field through this convenience
    translation, and it may not mix native display labels with canonical API
    keys. Dropdown arrays must contain exactly one reviewed choice.
    """

    supplied_keys = set(payload)
    native_keys = set(_NATIVE_PROMPT_FIELD_MAP)
    canonical_keys = set(_ALLOWED_FIELDS)
    uses_native_keys = bool(supplied_keys & native_keys)
    uses_canonical_keys = bool(supplied_keys & canonical_keys)
    if uses_native_keys and uses_canonical_keys:
        raise PocIntakeError("guided POC input cannot mix native prompt labels and canonical fields")
    if not uses_native_keys:
        return dict(payload)

    unexpected = sorted(supplied_keys - native_keys)
    if unexpected:
        raise PocIntakeError("guided POC input contains unsupported fields: {}".format(", ".join(unexpected)))

    canonical: Dict[str, Any] = {}
    for native_label, canonical_field in _NATIVE_PROMPT_FIELD_MAP.items():
        if native_label not in payload:
            continue
        value = payload[native_label]
        if native_label in _NATIVE_PROMPT_ARRAY_FIELDS:
            if not isinstance(value, list) or len(value) != 1:
                raise PocIntakeError("{} must contain exactly one selected value".format(native_label))
            value = value[0]
        elif isinstance(value, list):
            raise PocIntakeError("{} must be a single text value".format(native_label))
        canonical[canonical_field] = value
    return canonical


def sjc23_poc_requirements(payload: Mapping[str, Any], policy: Mapping[str, Any]) -> Dict[str, Any]:
    """Create a canonical SJC23 POC requirements document from form values.

    The adapter is deliberately profile-locked.  It fails closed unless the
    active API policy is the reviewed POC policy, which prevents this
    convenience endpoint from being used against a customer production policy.
    """

    _require_sjc23_poc_policy(policy)
    if not isinstance(payload, Mapping):
        raise PocIntakeError("guided POC input must be an object")
    payload = _canonical_poc_form_values(payload)
    unexpected = sorted(set(payload) - _ALLOWED_FIELDS)
    if unexpected:
        raise PocIntakeError("guided POC input contains unsupported fields: {}".format(", ".join(unexpected)))

    fabric_name = _required_text(payload, "fabric_name", _FABRIC_NAME)
    change_reference = _required_text(payload, "change_reference", _CHANGE_REFERENCE)
    corporate_users = _bounded_integer(payload, "corporate_users", 1, 200)
    guest_users = _bounded_integer(payload, "guest_users", 1, 200)
    lease_minutes = _bounded_integer(payload, "dhcp_lease_minutes", 30, 1440)

    if payload.get("corporate_attachment") != "corporate_laptop":
        raise PocIntakeError("corporate_attachment must select the approved Corporate laptop port")
    if payload.get("guest_attachment") != "guest_laptop":
        raise PocIntakeError("guest_attachment must select the approved Guest laptop port")
    dns_profile = payload.get("dns_profile")
    if dns_profile not in _DNS_PROFILES:
        raise PocIntakeError("dns_profile must select the approved POC resolver profile")

    profile = yaml.safe_load(SJC23_POC_PROFILE.read_text(encoding="utf-8"))
    if not isinstance(profile, dict):
        raise PocIntakeError("SJC23 POC profile is unavailable")
    requirements = deepcopy(profile)
    requirements["metadata"]["name"] = fabric_name
    requirements["metadata"]["change_reference"] = change_reference
    requirements["fabric"]["name"] = fabric_name

    demands = {"Corporate": corporate_users, "Guest": guest_users}
    for virtual_network in requirements["virtual_networks"]:
        virtual_network["sites"][0]["users"] = demands[virtual_network["name"]]
        dhcp = virtual_network["sites"][0]["dhcp"]
        dhcp["lease_minutes"] = lease_minutes
        dhcp["dns_servers"] = list(_DNS_PROFILES[dns_profile])

    attachment_ids = set(_ATTACHMENTS.values())
    if {attachment["id"] for attachment in requirements["endpoint_attachments"]} != attachment_ids:
        raise PocIntakeError("SJC23 POC attachment profile is invalid")
    return requirements
