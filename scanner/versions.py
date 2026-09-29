"""Version parsing, range validation and range matching.

Supported operators across pip- and npm-style specs:

    == != >= <= > < ~= (pip compatible release) ~ (npm tilde) ^ (npm caret)

Multiple constraints are joined by commas (pip) or whitespace (npm).
Wildcards ``*`` / ``x`` are accepted for equality pins (``==1.2.*``).

Anything malformed (``>=abc``, empty spec) or contradictory
(``>=2.0,<1.0``, ``==1.0,==2.0``) raises :class:`InvalidVersionRange`,
so callers can report *invalid range* distinctly from *missing version*.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_OP_RE = r"\^|~=|~|==|!=|>=|<=|=|>|<"
_TOKEN_RE = re.compile(rf"({_OP_RE})?\s*([0-9A-Za-z.*+_-]+)")
_NUMERIC_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)*")


class InvalidVersionRange(ValueError):
    """Raised when a version string/range is malformed or contradictory."""


@dataclass(frozen=True)
class Version:
    release: tuple[int, ...]
    raw: str


@dataclass(frozen=True)
class Constraint:
    op: str
    version: Version | None  # None for wildcard / "*"
    wildcard: tuple[int, ...] = ()  # prefix for ==X.*


def parse_version(text: str) -> Version:
    text = text.strip()
    if not text:
        raise InvalidVersionRange("empty version")
    if any(ch in text for ch in "*xX"):
        raise InvalidVersionRange(f"wildcard is not a concrete version: {text}")
    if text.endswith(("-", "+", ".")) or ".." in text:
        raise InvalidVersionRange(f"malformed version: {text}")
    core = text.split("+", 1)[0].split("-", 1)[0]
    m = _NUMERIC_RE.match(core)
    if not m or m.group(0) != core:
        raise InvalidVersionRange(f"not a numeric version: {text}")
    return Version(tuple(int(p) for p in core.split(".")), text)


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    pa, pb = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (pa > pb) - (pa < pb)


def _expand_bounds(c: Constraint) -> list[tuple[str, Version]]:
    """Expand ~=/~/^ into ordinary >= / < bounds for validation."""
    assert c.version is not None
    rel = c.version.release
    if c.op == "~=":  # ~=1.4.5 -> >=1.4.5,<1.5 ; ~=1.4 -> >=1.4,<2
        if len(rel) < 2:
            raise InvalidVersionRange(f"~= needs at least two segments: {c.version.raw}")
        upper = rel[:-1]
        upper = upper[:-1] + (upper[-1] + 1,)
        return [(">=", c.version), ("<", Version(upper, ""))]
    if c.op == "~":  # ~1.2.3 -> >=1.2.3,<1.3 ; ~1 -> >=1.0,<2
        if len(rel) >= 2:
            upper = rel[:1] + (rel[1] + 1,)
        else:
            upper = (rel[0] + 1,)
        return [(">=", c.version), ("<", Version(upper, ""))]
    if c.op == "^":  # npm caret with first-non-zero semantics
        idx = next((i for i, p in enumerate(rel) if p != 0), len(rel))
        if idx >= len(rel):  # ^0.0.0
            upper = rel[:-1] + (rel[-1] + 1,)
        else:
            upper = rel[:idx] + (rel[idx] + 1,)
        return [(">=", c.version), ("<", Version(upper, ""))]
    return [(c.op, c.version)]


def parse_constraints(spec: str) -> tuple[Constraint, ...]:
    spec = (spec or "").strip()
    if not spec:
        raise InvalidVersionRange("empty version range")
    normalized = spec.replace(",", " ")
    out: list[Constraint] = []
    pos = 0
    for m in _TOKEN_RE.finditer(normalized):
        if normalized[pos:m.start()].strip():
            raise InvalidVersionRange(f"unparseable range: {spec!r}")
        pos = m.end()
        op = m.group(1) or "=="
        if op == "=":
            op = "=="
        token = m.group(2)
        if token in ("*", "x", "X"):
            out.append(Constraint("*", None))
            continue
        if "*" in token or token.endswith(".x") or token.endswith(".X"):
            if op != "==":
                raise InvalidVersionRange(f"wildcard only allowed with ==: {spec!r}")
            prefix = tuple(
                int(p) for p in re.split(r"[.]", token) if p not in ("*", "x", "X")
            )
            if not prefix:
                out.append(Constraint("*", None))
            else:
                out.append(Constraint("==", None, wildcard=prefix))
            continue
        out.append(Constraint(op, parse_version(token)))
    if normalized[pos:].strip():
        raise InvalidVersionRange(f"unparseable range: {spec!r}")
    if not out:
        raise InvalidVersionRange(f"unparseable range: {spec!r}")
    _validate_satisfiable(out, spec)
    return tuple(out)


def _validate_satisfiable(constraints: list[Constraint], spec: str) -> None:
    expanded: list[tuple[str, Version]] = []
    wildcards: list[tuple[int, ...]] = []
    for c in constraints:
        if c.op == "*":
            continue
        if c.version is None:
            if c.wildcard:
                wildcards.append(c.wildcard)
        else:
            expanded.extend(_expand_bounds(c))
    lowers = [(op, v) for op, v in expanded if op in (">", ">=")]
    uppers = [(op, v) for op, v in expanded if op in ("<", "<=")]
    equals = [v for op, v in expanded if op == "=="]
    not_equals = [v for op, v in expanded if op == "!="]

    for lop, lv in lowers:
        for uop, uv in uppers:
            cmp_ = _cmp(lv.release, uv.release)
            if cmp_ > 0 or (cmp_ == 0 and (lop == ">" or uop == "<")):
                raise InvalidVersionRange(f"unsatisfiable range: {spec!r}")
    for ev in equals:
        for lop, lv in lowers:
            if not (_cmp(ev.release, lv.release) >= 0 and (lop == ">=" or _cmp(ev.release, lv.release) > 0)):
                raise InvalidVersionRange(f"unsatisfiable range: {spec!r}")
        for uop, uv in uppers:
            if not (_cmp(ev.release, uv.release) <= 0 and (uop == "<=" or _cmp(ev.release, uv.release) < 0)):
                raise InvalidVersionRange(f"unsatisfiable range: {spec!r}")
        for nv in not_equals:
            if _cmp(ev.release, nv.release) == 0:
                raise InvalidVersionRange(f"unsatisfiable range: {spec!r}")
        for prefix in wildcards:
            if ev.release[: len(prefix)] != prefix:
                raise InvalidVersionRange(f"unsatisfiable range: {spec!r}")
    if len(equals) >= 2 and any(_cmp(equals[0].release, v.release) != 0 for v in equals[1:]):
        raise InvalidVersionRange(f"unsatisfiable range: {spec!r}")


def validate_range(spec: str) -> None:
    parse_constraints(spec)


def _match_one(v: tuple[int, ...], op: str, c: Constraint) -> bool:
    if op == "*":
        return True
    if c.version is None:
        return v[: len(c.wildcard)] == c.wildcard
    target = c.version.release
    cmp_ = _cmp(v, target)
    if op == "==":
        return cmp_ == 0
    if op == "!=":
        return cmp_ != 0
    if op == ">=":
        return cmp_ >= 0
    if op == "<=":
        return cmp_ <= 0
    if op == ">":
        return cmp_ > 0
    if op == "<":
        return cmp_ < 0
    raise InvalidVersionRange(f"unknown operator: {op}")


def satisfies(version_text: str, spec: str) -> bool:
    v = parse_version(version_text)
    for c in parse_constraints(spec):
        if c.op in ("~=", "~", "^"):
            assert c.version is not None
            for op, bound in _expand_bounds(c):
                if not _match_one(v.release, op, Constraint(op, bound)):
                    return False
        elif not _match_one(v.release, c.op, c):
            return False
    return True


def is_concrete_version(spec: str) -> bool:
    try:
        cs = parse_constraints(spec)
    except InvalidVersionRange:
        return False
    return len(cs) == 1 and cs[0].op == "==" and cs[0].version is not None
