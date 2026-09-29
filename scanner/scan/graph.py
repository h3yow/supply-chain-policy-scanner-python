"""Dependency graph analysis.

Structural problems are surfaced as findings rather than silently resolved:

* ``CIRCULAR_DEPENDENCY``    - dependency cycle; every node on a cycle is listed;
* ``DUPLICATE_INTRODUCTION`` - same package@version introduced from >1 source;
* ``VERSION_CONFLICT``       - same package present at different concrete versions
                               (or a range entry alongside a concrete one).
"""
from __future__ import annotations

from collections import defaultdict

from scanner.models import (
    Decision,
    Finding,
    FindingCode,
    NormalizedManifest,
)


def _cycle_nodes(edges: tuple[tuple[str, str], ...]) -> list[list[str]]:
    """Return each elementary cycle via Tarjan SCC (SCC size > 1 or self-loop)."""
    adj: dict[str, set[str]] = defaultdict(set)
    nodes: set[str] = set()
    for a, b in edges:
        adj[a].add(b)
        nodes.update((a, b))

    index = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indices: dict[str, int] = {}
    low: dict[str, int] = {}
    cycles: list[list[str]] = []

    def strongconnect(v: str) -> None:
        nonlocal index
        indices[v] = low[v] = index
        index += 1
        stack.append(v)
        on_stack.add(v)
        for w in adj[v]:
            if w not in indices:
                strongconnect(w)
                low[v] = min(low[v], low[w])
            elif w in on_stack:
                low[v] = min(low[v], indices[w])
        if low[v] == indices[v]:
            comp: list[str] = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                comp.append(w)
                if w == v:
                    break
            if len(comp) > 1 or v in adj[v]:
                cycles.append(sorted(comp))

    for node in sorted(nodes):
        if node not in indices:
            strongconnect(node)
    return cycles


def analyze_graph(manifest: NormalizedManifest) -> tuple[Finding, ...]:
    findings: list[Finding] = []

    # --- duplicate introduction (identical package+version, multiple sources)
    pv_sources: dict[tuple[str, str], set[str]] = defaultdict(set)
    name_versions: dict[str, set[str]] = defaultdict(set)
    name_ranges: dict[str, set[str]] = defaultdict(set)
    for pkg in manifest.packages:
        pv_sources[(pkg.name, pkg.version)].add(pkg.introduced_by)
        if pkg.version:
            name_versions[pkg.name].add(pkg.version)
        if pkg.version_range and pkg.version_range.lstrip("=") != pkg.version:
            name_ranges[pkg.name].add(pkg.version_range)

    for (name, version), sources in sorted(pv_sources.items()):
        real_sources = {s for s in sources if s}
        if len(real_sources) > 1:
            findings.append(Finding(
                FindingCode.DUPLICATE_INTRODUCTION, Decision.WARN,
                f"{name}@{version or '<unpinned>'}",
                f"introduced {len(real_sources)} times via: "
                f"{', '.join(sorted(real_sources))}",
                basis=(f"same package/version appears in {len(real_sources)} entries: "
                       + ", ".join(sorted(real_sources)))))

    # --- version conflicts
    for name, versions in sorted(name_versions.items()):
        if len(versions) > 1:
            ordered = sorted(versions)
            findings.append(Finding(
                FindingCode.VERSION_CONFLICT, Decision.FAIL,
                name,
                f"multiple concrete versions present: {', '.join(ordered)}",
                basis=f"package {name!r} resolved to versions: {', '.join(ordered)}"))
    for name, ranges in sorted(name_ranges.items()):
        versions = name_versions.get(name, set())
        if versions or len(ranges) > 1:
            findings.append(Finding(
                FindingCode.VERSION_CONFLICT, Decision.WARN,
                name,
                f"version requirements disagree: {', '.join(sorted(ranges))}"
                + (f" against resolved {', '.join(sorted(versions))}" if versions else ""),
                basis=("range entries " + ", ".join(sorted(ranges))
                       + (" vs resolved " + ", ".join(sorted(versions)) if versions else ""))))

    # --- circular dependencies
    for cycle in _cycle_nodes(manifest.edges):
        chain = " -> ".join(cycle + [cycle[0]])
        for node in cycle:
            findings.append(Finding(
                FindingCode.CIRCULAR_DEPENDENCY, Decision.FAIL, node,
                f"participates in dependency cycle: {chain}",
                basis=f"cycle detected in edge set: {chain}"))

    # stable order for reproducibility
    return tuple(sorted(findings, key=lambda f: (f.code.value, f.subject, f.detail)))
