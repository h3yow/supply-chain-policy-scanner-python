"""Policy domain model: rules and policy documents with strict validation."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from scanner.errors import InvalidPolicyError
from scanner.versions import InvalidVersionRange, validate_range


class RuleEffect(str, Enum):
    DENY = "deny"
    ALLOW = "allow"


class RuleMatch(str, Enum):
    EXACT = "exact"
    PREFIX = "prefix"
    REGEX = "regex"


_VALID_ECOSYSTEMS = {"pypi", "npm", "*"}
_RULE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


@dataclass(frozen=True)
class PolicyRule:
    id: str
    effect: RuleEffect
    ecosystem: str
    package: str
    match: RuleMatch = RuleMatch.EXACT
    version_range: str = ""
    reason: str = ""

    def validate(self) -> None:
        if not self.id or not _RULE_ID_RE.match(self.id):
            raise InvalidPolicyError(
                f"invalid rule id: {self.id!r}", details={"rule_id": self.id}
            )
        if not isinstance(self.effect, RuleEffect):
            raise InvalidPolicyError(f"invalid effect on rule {self.id}")
        if self.ecosystem not in _VALID_ECOSYSTEMS:
            raise InvalidPolicyError(
                f"invalid ecosystem on rule {self.id}: {self.ecosystem!r}",
                details={"rule_id": self.id, "ecosystem": self.ecosystem},
            )
        if not self.package or not isinstance(self.package, str):
            raise InvalidPolicyError(
                f"missing package on rule {self.id}", details={"rule_id": self.id}
            )
        if self.match == RuleMatch.REGEX:
            try:
                re.compile(self.package)
            except re.error as exc:
                raise InvalidPolicyError(
                    f"invalid regex on rule {self.id}: {exc}",
                    details={"rule_id": self.id},
                ) from exc
        if self.version_range:
            try:
                validate_range(self.version_range)
            except InvalidVersionRange as exc:
                raise InvalidPolicyError(
                    f"invalid version_range on rule {self.id}: {exc}",
                    details={"rule_id": self.id, "version_range": self.version_range},
                ) from exc


@dataclass(frozen=True)
class PolicyDocument:
    name: str
    description: str = ""
    default_effect: RuleEffect = RuleEffect.ALLOW
    rules: tuple[PolicyRule, ...] = field(default_factory=tuple)

    def validate(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise InvalidPolicyError("policy name is required")
        if not isinstance(self.default_effect, RuleEffect):
            raise InvalidPolicyError("default_effect must be allow/deny")
        seen: set[str] = set()
        for rule in self.rules:
            rule.validate()
            if rule.id in seen:
                raise InvalidPolicyError(
                    f"duplicate rule id: {rule.id}", details={"rule_id": rule.id}
                )
            seen.add(rule.id)


def rule_from_dict(data: dict) -> PolicyRule:
    try:
        rule = PolicyRule(
            id=str(data["id"]),
            effect=RuleEffect(str(data["effect"]).lower()),
            ecosystem=str(data.get("ecosystem", "*")),
            package=str(data["package"]),
            match=RuleMatch(str(data.get("match", "exact")).lower()),
            version_range=str(data.get("version_range", "")),
            reason=str(data.get("reason", "")),
        )
    except KeyError as exc:
        raise InvalidPolicyError(f"rule missing field: {exc.args[0]}") from exc
    except ValueError as exc:
        raise InvalidPolicyError(f"rule has invalid enum value: {exc}") from exc
    return rule


def document_from_dict(data: dict) -> PolicyDocument:
    if not isinstance(data, dict):
        raise InvalidPolicyError("policy body must be an object")
    try:
        default = RuleEffect(str(data.get("default_effect", "allow")).lower())
        rules_raw = data.get("rules", [])
        if not isinstance(rules_raw, list):
            raise InvalidPolicyError("rules must be a list")
        doc = PolicyDocument(
            name=str(data["name"]),
            description=str(data.get("description", "")),
            default_effect=default,
            rules=tuple(rule_from_dict(r) for r in rules_raw),
        )
    except KeyError as exc:
        raise InvalidPolicyError(f"policy missing field: {exc.args[0]}") from exc
    doc.validate()
    return doc
