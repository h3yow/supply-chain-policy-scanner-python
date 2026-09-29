"""Application service wiring parser, policy store, engine and cache."""
from __future__ import annotations

from scanner.errors import ManifestRejectedError, PolicyVersionNotFoundError
from scanner.hashing import content_hash, scan_cache_key
from scanner.logging_setup import get_logger, log_event
from scanner.models import ManifestFormat, ScanResult
from scanner.parsers.base import parse_manifest
from scanner.policy.models import PolicyDocument
from scanner.policy.roles import RoleAuthorizer
from scanner.policy.store import PolicyStore
from scanner.scan.cache import ScanCache
from scanner.scan.engine import evaluate

logger = get_logger("service")


class ScannerService:
    def __init__(self, authorizer: RoleAuthorizer | None = None) -> None:
        self._cache = ScanCache()
        self._store = PolicyStore(on_change=self._on_policy_changed)
        self._authorizer = authorizer
        self._log = logger

    def _on_policy_changed(self) -> None:
        # Any register/publish/rollback changes what the *effective* policy
        # may become; dropping the cache is the conservative, correct action.
        self._cache.invalidate_all()
        log_event(self._log, "cache_invalidated", reason="policy_changed")

    @property
    def store(self) -> PolicyStore:
        return self._store

    @property
    def authorizer(self) -> RoleAuthorizer | None:
        return self._authorizer

    def set_authorizer(self, authorizer: RoleAuthorizer) -> None:
        self._authorizer = authorizer

    def resolve_policy(self, version: str | None) -> tuple[str, PolicyDocument]:
        if version is not None:
            try:
                return version, self._store.get_version(version)
            except PolicyVersionNotFoundError:
                raise
        return self._store.current()

    def scan(
        self,
        content: str,
        declared_format: ManifestFormat = ManifestFormat.AUTO,
        policy_version: str | None = None,
    ) -> ScanResult:
        chash = content_hash(content)
        pv, policy = self.resolve_policy(policy_version)
        fmt_name = declared_format.value
        key = scan_cache_key(content, pv, fmt_name)
        box: dict = {}

        def compute() -> ScanResult:
            manifest = parse_manifest(content, declared_format)
            box["manifest"] = manifest
            result = evaluate(manifest, policy, pv)
            log_event(
                self._log, "scan_computed",
                content_hash=chash, policy_version=pv,
                decision=result.decision.value,
                package_count=result.package_count,
                rejected_count=result.rejected_count,
                basis=[f.basis for f in result.findings],
            )
            return result

        result = self._cache.get_or_compute(key, compute)
        # Defensive: never leak a result bound to a different policy version.
        if result.policy_version != pv:
            self._cache.invalidate_all()
            box.clear()
            result = self._cache.get_or_compute(
                scan_cache_key(content, pv, fmt_name), compute)

        log_event(
            self._log, "scan_served",
            content_hash=chash, policy_version=pv,
            decision=result.decision.value,
            finding_codes=sorted({f.code.value for f in result.findings}),
        )

        if result.rejected_count > 0:
            manifest = box.get("manifest")
            if manifest is None:  # served from cache: parse only to quote rows
                manifest = parse_manifest(content, declared_format)
            raise ManifestRejectedError(
                f"manifest contains {result.rejected_count} rejected entr"
                f"{'y' if result.rejected_count == 1 else 'ies'}",
                details={
                    "content_hash": chash,
                    "policy_version": pv,
                    "decision": result.decision.value,
                    "rejections": [
                        {"index": r.index, "reason": r.reason.value,
                         "raw": r.raw, "detail": r.detail}
                        for r in manifest.rejections
                    ],
                    "result": _result_payload(result),
                },
            )
        return result


def _result_payload(result: ScanResult) -> dict:
    return {
        "content_hash": result.content_hash,
        "policy_version": result.policy_version,
        "decision": result.decision.value,
        "package_count": result.package_count,
        "rejected_count": result.rejected_count,
        "findings": [
            {"code": f.code.value, "decision": f.decision.value,
             "subject": f.subject, "detail": f.detail, "basis": f.basis}
            for f in result.findings
        ],
    }


def result_to_dict(result: ScanResult) -> dict:
    return _result_payload(result)
