"""Versioned, in-memory policy store.

Lifecycle:

* ``register``  - publisher registers a *draft* document, returns a draft id;
* ``publish``   - a draft becomes the immutable current version ("v1", "v2", ...);
* ``rollback``  - republishing the document of any prior version creates a NEW
                  current version (never mutates history);

Rollback to missing versions and publishing unknown drafts fail with
distinguishable codes. Every state-changing call bumps an ``epoch`` and
fires a callback so scan caches can drop conclusions computed under an old
effective policy.
"""
from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass

from scanner.errors import PolicyNotFoundError, PolicyVersionNotFoundError
from scanner.policy.models import PolicyDocument


@dataclass(frozen=True)
class _Draft:
    draft_id: str
    document: PolicyDocument


class PolicyStore:
    def __init__(self, on_change: Callable[[], None] | None = None) -> None:
        self._lock = threading.RLock()
        self._drafts: dict[str, _Draft] = {}
        self._versions: list[PolicyDocument] = []
        self._on_change = on_change
        self._epoch = 0

    @staticmethod
    def _label(n: int) -> str:
        return f"v{n}"

    def _bump(self, notify: bool) -> None:
        self._epoch += 1
        if notify and self._on_change is not None:
            self._on_change()

    def epoch(self) -> int:
        with self._lock:
            return self._epoch

    def register(self, document: PolicyDocument, *, actor_role: str) -> str:
        document.validate()
        with self._lock:
            draft_id = uuid.uuid4().hex
            self._drafts[draft_id] = _Draft(draft_id, document)
            # A draft cannot affect the effective policy; bump epoch for
            # observability but do not invalidate scan results.
            self._bump(notify=False)
            return draft_id

    def publish(self, draft_id: str, *, actor_role: str) -> str:
        with self._lock:
            draft = self._drafts.get(draft_id)
            if draft is None:
                raise PolicyNotFoundError(
                    f"draft not found: {draft_id}", details={"draft_id": draft_id}
                )
            self._versions.append(draft.document)
            del self._drafts[draft_id]
            self._bump(notify=True)
            return self._label(len(self._versions))

    def rollback(self, version: str, *, actor_role: str) -> str:
        with self._lock:
            doc = self.get_version(version)  # raises PolicyVersionNotFoundError
            self._versions.append(doc)
            self._bump(notify=True)
            return self._label(len(self._versions))

    def current(self) -> tuple[str, PolicyDocument]:
        with self._lock:
            if not self._versions:
                raise PolicyVersionNotFoundError("no policy has been published yet")
            label = self._label(len(self._versions))
            return label, self._versions[-1]

    def get_version(self, version: str) -> PolicyDocument:
        with self._lock:
            if not version.startswith("v") or not version[1:].isdigit():
                raise PolicyVersionNotFoundError(
                    f"bad version label: {version!r}", details={"version": version}
                )
            n = int(version[1:])
            if n < 1 or n > len(self._versions):
                raise PolicyVersionNotFoundError(
                    f"version not found: {version}", details={"version": version}
                )
            return self._versions[n - 1]

    def list_versions(self) -> list[str]:
        with self._lock:
            return [self._label(i) for i in range(1, len(self._versions) + 1)]

    def list_drafts(self) -> list[dict]:
        with self._lock:
            return [
                {"draft_id": d.draft_id, "name": d.document.name, "rules": len(d.document.rules)}
                for d in self._drafts.values()
            ]
