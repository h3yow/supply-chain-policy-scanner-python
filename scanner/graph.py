"""依赖图分析：循环依赖、重复引入、版本冲突。"""
from __future__ import annotations

from collections import defaultdict

from .models import Dependency, GraphIssue, IssueKind
from .versions import InvalidVersionSpec, intersects, parse_spec


def analyze(dependencies: list[Dependency]) -> list[GraphIssue]:
    """对归一化依赖列表做图分析，返回问题列表（不静默取舍，全部标记）。"""
    issues: list[GraphIssue] = []
    issues.extend(_find_duplicates_and_conflicts(dependencies))
    issues.extend(_find_cycles(dependencies))
    return issues


def _find_duplicates_and_conflicts(dependencies: list[Dependency]) -> list[GraphIssue]:
    issues: list[GraphIssue] = []
    by_name: dict[str, list[Dependency]] = defaultdict(list)
    for dep in dependencies:
        by_name[dep.name].append(dep)
    for name, entries in sorted(by_name.items()):
        if len(entries) < 2:
            continue
        specs = [e.spec for e in entries]
        # 重复引入：同一包出现多次且约束完全一致
        if len(set(specs)) == 1:
            issues.append(GraphIssue(
                IssueKind.DUPLICATE,
                f"package {name!r} introduced {len(entries)} times with identical spec {specs[0]!r}",
                (name,),
            ))
            continue
        # 版本冲突：同名包的约束两两无交集（无法解析的约束此前已被拒绝，这里再防御一次）
        parsed = []
        for spec in specs:
            try:
                parsed.append(parse_spec(spec))
            except InvalidVersionSpec:
                parsed.append(None)
        conflict_pairs = []
        for i in range(len(parsed)):
            for j in range(i + 1, len(parsed)):
                a, b = parsed[i], parsed[j]
                if a is not None and b is not None and not intersects(a, b):
                    conflict_pairs.append((specs[i], specs[j]))
        if conflict_pairs:
            pairs = ", ".join(f"{a!r} vs {b!r}" for a, b in conflict_pairs)
            issues.append(GraphIssue(
                IssueKind.VERSION_CONFLICT,
                f"package {name!r} has disjoint version constraints: {pairs}",
                (name,),
            ))
        else:
            issues.append(GraphIssue(
                IssueKind.DUPLICATE,
                f"package {name!r} introduced multiple times with compatible specs {sorted(set(specs))}",
                (name,),
            ))
    return issues


def _find_cycles(dependencies: list[Dependency]) -> list[GraphIssue]:
    by_name: dict[str, Dependency] = {}
    for dep in dependencies:
        by_name.setdefault(dep.name, dep)
    issues: list[GraphIssue] = []
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {name: WHITE for name in by_name}
    stack: list[str] = []
    reported: set[frozenset[str]] = set()

    def dfs(node: str) -> None:
        color[node] = GRAY
        stack.append(node)
        for nxt in by_name[node].depends_on:
            if nxt not in by_name:
                continue
            if color[nxt] == GRAY:
                cycle = tuple(stack[stack.index(nxt):] + [nxt])
                key = frozenset(cycle)
                if key not in reported:
                    reported.add(key)
                    issues.append(GraphIssue(
                        IssueKind.CYCLE,
                        "dependency cycle: " + " -> ".join(cycle),
                        tuple(sorted(key)),
                    ))
            elif color[nxt] == WHITE:
                dfs(nxt)
        stack.pop()
        color[node] = BLACK

    for name in sorted(by_name):
        if color[name] == WHITE:
            dfs(name)
    return issues
