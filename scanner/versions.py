"""版本约束解析与区间判定。"""
from __future__ import annotations

import re
from dataclasses import dataclass

_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)*)(?:[-.]?((?:a|b|rc|alpha|beta|pre|preview|dev)\.?\d*))?$", re.IGNORECASE)
_CLAUSE_RE = re.compile(r"^(>=|<=|==|!=|~=|>|<)?\s*(.+)$")


@dataclass(frozen=True, order=True)
class Version:
    """归一化版本号（release 段 + 预发布标记）。"""

    release: tuple[int, ...]
    prerelease: str = ""

    def __str__(self) -> str:
        base = ".".join(str(p) for p in self.release)
        return f"{base}-{self.prerelease}" if self.prerelease else base


class InvalidVersionSpec(ValueError):
    """版本约束非法。"""


def _normalize(release: tuple[int, ...], width: int = 3) -> tuple[int, ...]:
    padded = release + (0,) * max(0, width - len(release))
    return padded


def parse_version(text: str) -> Version:
    """解析单个版本号，非法时抛 InvalidVersionSpec。"""
    text = text.strip()
    m = _VERSION_RE.match(text)
    if not m:
        raise InvalidVersionSpec(f"invalid version: {text!r}")
    release = tuple(int(p) for p in m.group(1).split("."))
    prerelease = (m.group(2) or "").lower()
    return Version(release=release, prerelease=prerelease)


def _cmp(a: Version, b: Version) -> int:
    width = max(len(a.release), len(b.release), 3)
    ra, rb = _normalize(a.release, width), _normalize(b.release, width)
    if ra != rb:
        return -1 if ra < rb else 1
    # 预发布版本早于同 release 的正式版
    if a.prerelease == b.prerelease:
        return 0
    if not a.prerelease:
        return 1
    if not b.prerelease:
        return -1
    return -1 if a.prerelease < b.prerelease else 1


@dataclass(frozen=True)
class _Clause:
    op: str
    version: Version

    def matches(self, v: Version) -> bool:
        c = _cmp(v, self.version)
        if self.op in ("", "=="):
            return c == 0
        if self.op == "!=":
            return c != 0
        if self.op == ">=":
            return c >= 0
        if self.op == "<=":
            return c <= 0
        if self.op == ">":
            return c > 0
        if self.op == "<":
            return c < 0
        if self.op == "~=":
            # PEP 440 兼容版本：>= 当前，且主版本段一致
            if c < 0:
                return False
            upper = self.version.release[:-1] or self.version.release[:1]
            width = max(len(upper), 1)
            return _normalize(v.release, width)[: len(upper)] == _normalize(upper, width)
        raise InvalidVersionSpec(f"unknown operator: {self.op!r}")


class Spec:
    """版本约束集合（逗号分隔的 AND 语义），支持 contains 判定。"""

    def __init__(self, clauses: tuple[_Clause, ...], raw: str) -> None:
        self._clauses = clauses
        self.raw = raw

    def contains(self, version: Version) -> bool:
        return all(c.matches(version) for c in self._clauses)

    def __repr__(self) -> str:
        return f"Spec({self.raw!r})"


def _expand_caret(ver: Version) -> tuple[_Clause, _Clause]:
    """^1.2.3 -> >=1.2.3 <2.0.0；^0.2.3 -> >=0.2.3 <0.3.0；^0.0.3 -> >=0.0.3 <0.0.4"""
    rel = _normalize(ver.release, 3)
    for i, part in enumerate(rel):
        if part != 0:
            upper = list(rel[: i + 1])
            upper[i] += 1
            upper += [0] * (3 - len(upper))
            return (
                _Clause(">=", ver),
                _Clause("<", Version(tuple(upper[:3]))),
            )
    return (_Clause(">=", ver), _Clause("<", Version((0, 0, 1))))


def _expand_tilde(ver: Version) -> tuple[_Clause, _Clause]:
    """~1.2.3 -> >=1.2.3 <1.3.0；~1.2 -> >=1.2 <1.3.0；~1 -> >=1 <2.0.0"""
    rel = ver.release
    if len(rel) <= 1:
        upper = (rel[0] + 1, 0, 0)
    else:
        upper = (rel[0], rel[1] + 1, 0)
    return (_Clause(">=", ver), _Clause("<", Version(upper)))


def parse_spec(spec: str) -> Spec:
    """解析版本约束（如 '>=1.0,<2.0'、'^1.2'、'~1.2.3'、'*'、'1.2.3'）。"""
    raw = spec.strip()
    if raw in ("", "*"):
        return Spec((), raw or "*")
    clauses: list[_Clause] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            raise InvalidVersionSpec(f"empty clause in spec: {raw!r}")
        if part.startswith("^"):
            clauses.extend(_expand_caret(parse_version(part[1:])))
            continue
        if part.startswith("~") and not part.startswith("~="):
            clauses.extend(_expand_tilde(parse_version(part[1:])))
            continue
        m = _CLAUSE_RE.match(part)
        if not m:
            raise InvalidVersionSpec(f"invalid clause: {part!r}")
        op = m.group(1) or "=="
        if op == "=":
            op = "=="
        ver_text = m.group(2).strip()
        if ver_text.endswith(".*"):
            if op not in ("==", "!="):
                raise InvalidVersionSpec(f"wildcard only allowed with ==/!=: {part!r}")
            prefix = ver_text[:-2]
            base = parse_version(prefix)
            upper_rel = base.release[:-1] + (base.release[-1] + 1,)
            clauses.append(_Clause(">=" if op == "==" else "<", base))
            clauses.append(_Clause("<" if op == "==" else ">=", Version(upper_rel)))
            continue
        clauses.append(_Clause(op, parse_version(ver_text)))
    return Spec(tuple(clauses), raw)


def intersects(a: Spec, b: Spec) -> bool:
    """启发式判定两个约束是否存在共同版本：取双方边界点及边界微增版本做候选。"""
    candidates: list[Version] = []
    for spec in (a, b):
        for clause in spec._clauses:
            v = clause.version
            candidates.append(v)
            bumped = v.release[:-1] + (v.release[-1] + 1,)
            candidates.append(Version(bumped, v.prerelease))
    if not candidates:
        return True  # 双方都是 '*'，必然相交
    return any(a.contains(c) and b.contains(c) for c in candidates)
