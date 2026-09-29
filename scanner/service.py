"""扫描服务编排：解析 -> 图分析 -> 策略判定 -> 缓存。"""
from __future__ import annotations

import hashlib
import logging

from .cache import ScanCache
from .graph import analyze
from .models import (
    Decision,
    Dependency,
    IssueKind,
    Policy,
    ScanReport,
    VerdictItem,
)
from .parsers import parse_manifest
from .policy import PolicyRegistry
from .versions import InvalidVersionSpec, parse_spec

logger = logging.getLogger("scanner.service")


class ScanService:
    """对外扫描入口，保证同清单同策略版本结论可复现。"""

    def __init__(self, registry: PolicyRegistry, cache: ScanCache | None = None) -> None:
        self._registry = registry
        self._cache = cache or ScanCache()
        # 策略发布 / 回滚后，非当前版本的缓存条目一律失效，避免返回旧结论
        self._registry.add_listener(self._on_policy_changed)

    def _on_policy_changed(self, event: str, version: int) -> None:
        removed = self._cache.invalidate_except(version)
        logger.info("policy %s to version=%d, cache entries removed=%d", event, version, removed)

    def scan(self, token: str | None, content: bytes) -> ScanReport:
        """扫描清单内容，返回带内容哈希与策略版本的判定报告。"""
        policy = self._registry.current(token)  # 鉴权：只读角色即可；无生效策略会抛错
        content_hash = hashlib.sha256(content).hexdigest()
        key = (content_hash, policy.version)
        return self._cache.get_or_compute(key, lambda: self._compute(content_hash, content, policy))

    def _compute(self, content_hash: str, content: bytes, policy: Policy) -> ScanReport:
        parsed = parse_manifest(content)
        report = ScanReport(
            content_hash=content_hash,
            policy_version=policy.version,
            decision=Decision.ALLOW,
            errors=parsed.errors,
        )
        if not parsed.ok:
            report.decision = Decision.DENY
            for err in parsed.errors:
                logger.warning(
                    "scan rejected: content_hash=%s policy_version=%d reason=%s detail=%s location=%s",
                    content_hash, policy.version, err.reason.value, err.detail, err.location,
                )
            return report

        report.issues = analyze(parsed.dependencies)
        report.items = [self._evaluate(dep, policy) for dep in parsed.dependencies]

        blocking = {IssueKind.CYCLE, IssueKind.VERSION_CONFLICT}
        denied_items = [i for i in report.items if i.decision is Decision.DENY]
        blocking_issues = [i for i in report.issues if i.kind in blocking]
        if denied_items or blocking_issues:
            report.decision = Decision.DENY

        logger.info(
            "scan completed: content_hash=%s policy_version=%d decision=%s "
            "dependencies=%d denied=%d issues=%s",
            content_hash, policy.version, report.decision.value,
            len(report.items), len(denied_items),
            [f"{i.kind.value}:{','.join(i.packages)}" for i in report.issues],
        )
        return report

    def _evaluate(self, dep: Dependency, policy: Policy) -> VerdictItem:
        """逐项判定并给出依据。"""
        name_key = dep.name.lower()
        denied_names = {p.lower() for p in policy.denied_packages}
        if name_key in denied_names:
            return VerdictItem(dep.name, dep.spec, Decision.DENY,
                               f"package {dep.name!r} is denied by policy v{policy.version}")
        if dep.license and dep.license.lower() in {l.lower() for l in policy.denied_licenses}:
            return VerdictItem(dep.name, dep.spec, Decision.DENY,
                               f"license {dep.license!r} is denied by policy v{policy.version}")
        if not policy.allow_prerelease:
            try:
                spec = parse_spec(dep.spec)
            except InvalidVersionSpec:
                spec = None
            if spec is not None and any(c.version.prerelease for c in spec._clauses):
                return VerdictItem(dep.name, dep.spec, Decision.DENY,
                                   f"prerelease version in spec {dep.spec!r} not allowed by policy v{policy.version}")
        return VerdictItem(dep.name, dep.spec, Decision.ALLOW, "no policy rule matched")
