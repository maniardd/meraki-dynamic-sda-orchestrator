"""Fail-closed API token authentication without stored bearer-token values."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, Mapping, Optional


TOKEN_DIGEST = re.compile(r"^[0-9a-f]{64}$")
ACTOR = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")
ALLOWED_ROLES = {"viewer", "planner", "approver", "operator", "auditor"}


class AuthenticationConfigError(RuntimeError):
    pass


def token_sha256(token: str) -> str:
    candidate = str(token)
    if len(candidate) < 32 or "\n" in candidate or "\r" in candidate:
        return ""
    return hashlib.sha256(candidate.encode("utf-8")).hexdigest()


def load_hashed_token_identities(path: str) -> Dict[str, Dict[str, Any]]:
    token_path = Path(path).expanduser().resolve()
    try:
        details = token_path.stat()
    except OSError as exc:
        raise AuthenticationConfigError("Token identity file is unavailable") from exc
    if not stat.S_ISREG(details.st_mode):
        raise AuthenticationConfigError("Token identity path must be a regular file")
    if os.name != "nt" and details.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise AuthenticationConfigError(
            "Token identity file must not be accessible by group or other"
        )
    try:
        document = json.loads(token_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AuthenticationConfigError("Token identity file is invalid") from exc
    if not isinstance(document, Mapping) or document.get("version") != 1:
        raise AuthenticationConfigError("Token identity file version is unsupported")
    identities = document.get("identities")
    if not isinstance(identities, Mapping) or not identities:
        raise AuthenticationConfigError("Token identity file has no identities")

    validated: Dict[str, Dict[str, Any]] = {}
    for digest, raw_principal in identities.items():
        if not TOKEN_DIGEST.fullmatch(str(digest)):
            raise AuthenticationConfigError("Token identity digest is invalid")
        if not isinstance(raw_principal, Mapping):
            raise AuthenticationConfigError("Token identity principal is invalid")
        actor = str(raw_principal.get("actor", ""))
        roles = raw_principal.get("roles")
        if not ACTOR.fullmatch(actor):
            raise AuthenticationConfigError("Token identity actor is invalid")
        if not isinstance(roles, list) or not roles:
            raise AuthenticationConfigError("Token identity roles are invalid")
        normalized_roles = {str(role) for role in roles}
        if not normalized_roles.issubset(ALLOWED_ROLES):
            raise AuthenticationConfigError("Token identity contains an unsupported role")
        validated[str(digest)] = {
            "actor": actor,
            "roles": sorted(normalized_roles),
        }
    return validated


def match_hashed_principal(
    supplied_token: str,
    identities: Mapping[str, Mapping[str, Any]],
) -> Optional[Dict[str, Any]]:
    supplied_digest = token_sha256(supplied_token)
    if not supplied_digest:
        return None
    matched: Optional[Mapping[str, Any]] = None
    for configured_digest, principal in identities.items():
        if hmac.compare_digest(supplied_digest, str(configured_digest)):
            matched = principal
    if matched is None:
        return None
    return {
        "actor": str(matched["actor"]),
        "roles": {str(role) for role in matched["roles"]},
    }
