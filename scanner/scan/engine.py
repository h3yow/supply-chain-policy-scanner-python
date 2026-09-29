"""Rule evaluation engine.

Applies one immutable :class:`PolicyDocument` to a normalized manifest and
produces a fully reproducible :class:`ScanResult`. Every finding carries a
human/machine readable ``basis`` naming the rule and inputs that decided it.
"""
from __future__ import annotations

import re

from scanner.models import (
    Decision,
    Finding,
    FindingCode,
    NormalizedManifest,
    Package,
    ScanResult,
)
from scanner.policy.models import PolicyDocument, RuleEffect, RuleMatch
from scanner.scan.graph import analyze_graph
from scanner.versions import satisfies

_DECISION_RANK = {Decision.PASS: 0, Decision.WARN: 1, Decision.FAIL: 2}


def _rule_matches(rule, pkg: Package) -> bool:
    if rule.ecosystem != "*" and rule.ecosystem != pkg.ecosystem.value:
        return False
    if rule.match is RuleMatch.EXACT:
        if rule.package != pkg.name:
            return False
    elif rule.match is RuleMatch.PREFIX:
        if not pkg.name.startswith(rule.package):
            return False
    elif rule.match is RuleMatch.REGEX:
        if re.search(rule.package, pkg.name) is None:
            return False
    if rule.version_range and pkg.version:
        if not satisfies(pkg.version, rule.version_range):
            return False
    elif rule.version_range and not pkg.version:
        # cannot prove an unpinned/range-only entry satisfies a version rule
        return False
    return True


def _basis(rule, pkg: Package) -> str:
    bits = [f"rule {rule.id}", f"effect={rule.effect.value}",
            f"ecosystem={rule.ecosystem}", f"match={rule.match.value}:{rule.package}"]
    if rule.version_range:
        bits.append(f"version_range={rule.version_range}")
    bits.append(f"package={pkg.name}@{pkg.version or pkg.version_range or '?'}")
    bits.append(f"source={pkg.introduced_by}")
    return "; ".join(bits)


def evaluate(
    manifest: NormalizedManifest,
    policy: PolicyDocument,
    policy_version: str,
) -> ScanResult:
    findings: list[Finding] = []

    # Parse rejections: malformed entries are part of the verdict, never silent.
    for rej in manifest.rejections:
        findings.append(Finding(
            FindingCode.ENTRY_REJECTED, Decision.WARN,
            f"entry#{rej.index}",
            f"{rej.reason.value}: {rej.detail}",
            basis=(f"parser rejected entry at index {rej.index} "
                   f"with reason {rej.reason.value}; raw={rej.raw!r}")))

    # Policy rules are evaluated in declared order; a deny match is terminal
    # for that package, otherwise the first matching allow rule explains it.
    for pkg in manifest.packages:
        matched_deny = None
        matched_allow = None
        for rule in policy.rules:
            if not _rule_matches(rule, pkg):
                continue
            if rule.effect is RuleEffect.DENY and matched_deny is None:
                matched_deny = rule
                break
            if rule.effect is RuleEffect.ALLOW and matched_allow is None:
                matched_allow = rule
        if matched_deny is not None:
            findings.append(Finding(
                FindingCode.DENIED_PACKAGE, Decision.FAIL,
                f"{pkg.name}@{pkg.version or pkg.version_range or '?'}",
                matched_deny.reason or f"denied by rule {matched_deny.id}",
                basis=_basis(matched_deny, pkg)))
        elif matched_allow is not None:
            findings.append(Finding(
                FindingCode.ALLOWED_PACKAGE, Decision.PASS,
                f"{pkg.name}@{pkg.version or pkg.version_range or '?'}",
                f"explicitly allowed by rule {matched_allow.id}",
                basis=_basis(matched_allow, pkg)))
        else:
            default = (Decision.FAIL if policy.default_effect is RuleEffect.DENY
                       else Decision.PASS)
            code = (FindingCode.DENIED_PACKAGE if default is Decision.FAIL
                    else FindingCode.UNKNOWN_PACKAGE)
            findings.append(Finding(
                code, default,
                f"{pkg.name}@{pkg.version or pkg.version_range or '?'}",
                (f"no rule matched; denied by policy default"
                 if default is Decision.FAIL
                 else "no rule matched; allowed by policy default"),
                basis=(f"default_effect={policy.default_effect.value}; "
                       f"no rule matched {pkg.name} ({pkg.ecosystem.value})")))

    findings.extend(analyze_graph(manifest))

    findings.sort(key=lambda f: (f.code.value, f.subject, f.detail))
    decision = Decision.PASS
    for f in findings:
        if _DECISION_RANK[f.decision] > _DECISION_RANK[decision]:
            decision = f.decision

    return ScanResult(
        content_hash=manifest.content_hash,
        policy_version=policy_version,
        decision=decision,
        findings=tuple(findings),
        package_count=len(manifest.packages),
        rejected_count=len(manifest.rejections),
    )
