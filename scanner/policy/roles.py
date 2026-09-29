"""Role / API-key enforcement.

Failure modes are deliberately distinguishable:

* missing/unknown key  -> ``AuthenticationError`` (401, code authentication_required)
* known reader performing a publisher action
                       -> ``PermissionDeniedError`` (403, code permission_denied)
"""
from __future__ import annotations

from scanner.config import RoleConfig
from scanner.errors import AuthenticationError, PermissionDeniedError

ROLE_READER = "reader"
ROLE_PUBLISHER = "publisher"
_ROLE_ORDER = {ROLE_READER: 1, ROLE_PUBLISHER: 2}


class RoleAuthorizer:
    def __init__(self, config: RoleConfig) -> None:
        self._config = config

    def authenticate(self, api_key: str | None) -> str:
        if not api_key:
            raise AuthenticationError("missing API key")
        if api_key in self._config.publish_keys:
            return ROLE_PUBLISHER
        if api_key in self._config.read_keys:
            return ROLE_READER
        raise AuthenticationError("unknown API key")

    def require_role(self, api_key: str | None, required: str) -> str:
        role = self.authenticate(api_key)
        if _ROLE_ORDER[role] < _ROLE_ORDER[required]:
            raise PermissionDeniedError(
                f"role {role!r} may not perform publisher-only operation",
                details={"role": role, "required": required},
            )
        return role
