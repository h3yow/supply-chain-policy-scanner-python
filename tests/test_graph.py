from scanner.graph import analyze
from scanner.models import Dependency, IssueKind


def kinds(issues):
    return {i.kind for i in issues}


def test_cycle_detected():
    deps = [Dependency("a", "1.0", ("b",)), Dependency("b", "1.0", ("c",)), Dependency("c", "1.0", ("a",))]
    issues = analyze(deps)
    cycle = next(i for i in issues if i.kind is IssueKind.CYCLE)
    assert set(cycle.packages) == {"a", "b", "c"}


def test_self_cycle_detected():
    issues = analyze([Dependency("a", "1.0", ("a",))])
    assert IssueKind.CYCLE in kinds(issues)


def test_duplicate_identical_specs():
    issues = analyze([Dependency("x", ">=1.0"), Dependency("x", ">=1.0")])
    assert kinds(issues) == {IssueKind.DUPLICATE}


def test_version_conflict_disjoint_specs():
    issues = analyze([Dependency("y", ">=2.0"), Dependency("y", "<2.0")])
    assert IssueKind.VERSION_CONFLICT in kinds(issues)
    assert IssueKind.DUPLICATE not in kinds(issues)


def test_compatible_multiple_specs_flagged_as_duplicate_not_conflict():
    issues = analyze([Dependency("z", ">=1.0,<3.0"), Dependency("z", ">=2.0")])
    assert IssueKind.DUPLICATE in kinds(issues)
    assert IssueKind.VERSION_CONFLICT not in kinds(issues)


def test_clean_graph_has_no_issues():
    deps = [Dependency("a", "1.0", ("b",)), Dependency("b", "2.0")]
    assert analyze(deps) == []
