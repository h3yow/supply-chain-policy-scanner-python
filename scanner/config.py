"""Static local configuration: roles and their API keys.

Two roles exist:

* ``reader``    - may scan manifests and read policy metadata/versions;
* ``publisher`` - may additionally register, publish and roll back policies.

Keys are read from environment variables when present, otherwise from the
built-in local defaults (clearly marked as demo-only).
"""
from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_READ_KEYS = frozenset({"reader-local-key"})
DEFAULT_PUBLISH_KEYS = frozenset({"publisher-local-key"})


@dataclass(frozen=True)
class RoleConfig:
    read_keys: frozenset[str]
    publish_keys: frozenset[str]


def _keys_from_env(name: str, default: frozenset[str]) -> frozenset[str]:
    raw = os.environ.get(name)
    if not raw:
        return default
    return frozenset(k.strip() for k in raw.split(",") if k.strip())


def load_roles() -> RoleConfig:
    return RoleConfig(
        read_keys=_keys_from_env("SCANNER_READ_KEYS", DEFAULT_READ_KEYS),
        publish_keys=_keys_from_env("SCANNER_PUBLISH_KEYS", DEFAULT_PUBLISH_KEYS),
    )
