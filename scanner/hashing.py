"""Stable content hashing for manifests and cache keys."""
from __future__ import annotations

import hashlib
import json


def content_hash(content: str | bytes) -> str:
    """Return the canonical SHA-256 hex digest of raw manifest content."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def scan_cache_key(content: str | bytes, policy_version: str, fmt: str) -> str:
    """Cache key bound to both content and the *exact* policy version.

    Including the policy version guarantees that a publish or rollback can
    never be served a stale conclusion: version ``v3`` and ``v2`` have
    disjoint key spaces even for byte-identical manifests.
    """
    return hashlib.sha256(
        json.dumps(
            {"h": content_hash(content), "pv": policy_version, "f": fmt},
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
