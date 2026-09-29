import logging
import threading
import time

from scanner.cache import ScanCache
from scanner.models import Decision, IssueKind, Policy, RejectReason
from scanner.policy import PolicyRegistry
from scanner.service import ScanService

PUB = "publisher-token"
RO = "readonly-token"

MANIFEST = b"flask>=2.0\nrequests==2.31.0\n"


def make_service(*policies, publish=None):
    reg = PolicyRegistry()
    for p in policies:
        reg.register(PUB, p)
    if publish is not None:
        reg.publish(PUB, publish)
    cache = ScanCache()
    return ScanService(reg, cache), reg, cache


def test_scan_reproducible_with_policy_version():
    svc, _, _ = make_service(Policy(version=1), publish=1)
    r1 = svc.scan(RO, MANIFEST)
    r2 = svc.scan(RO, MANIFEST)
    assert r1.decision is Decision.ALLOW
    assert r1.policy_version == 1 and r2.policy_version == 1
    assert r1.content_hash == r2.content_hash
    assert r1 is r2  # 缓存命中，同一对象


def test_denied_package_deny_with_reason():
    svc, _, _ = make_service(Policy(version=1, denied_packages={"flask"}), publish=1)
    report = svc.scan(RO, MANIFEST)
    assert report.decision is Decision.DENY
    item = next(i for i in report.items if i.name == "flask")
    assert item.decision is Decision.DENY and "denied by policy v1" in item.reason


def test_malformed_manifest_denied_with_distinguishable_reasons():
    svc, _, _ = make_service(Policy(version=1), publish=1)
    report = svc.scan(RO, b"flask>=abc\nrequests\n")
    assert report.decision is Decision.DENY
    reasons = {e.reason for e in report.errors}
    assert reasons == {RejectReason.INVALID_VERSION_SPEC, RejectReason.MISSING_VERSION}


def test_cycle_and_conflict_block_allow():
    svc, _, _ = make_service(Policy(version=1), publish=1)
    doc = b'''{"bomFormat": "CycloneDX", "components": [
      {"name": "a", "version": "1.0.0"}, {"name": "b", "version": "1.0.0"}],
      "dependencies": [{"ref": "a@1.0.0", "dependsOn": ["b@1.0.0"]},
                       {"ref": "b@1.0.0", "dependsOn": ["a@1.0.0"]}]}'''
    report = svc.scan(RO, doc)
    assert report.decision is Decision.DENY
    assert any(i.kind is IssueKind.CYCLE for i in report.issues)


def test_duplicate_only_does_not_deny():
    svc, _, _ = make_service(Policy(version=1), publish=1)
    report = svc.scan(RO, b"flask>=2.0\nflask>=2.0\n")
    assert report.decision is Decision.ALLOW
    assert any(i.kind is IssueKind.DUPLICATE for i in report.issues)


def test_concurrent_identical_content_computed_once():
    svc, _, cache = make_service(Policy(version=1), publish=1)
    calls = []
    original = svc._compute

    def counting_compute(*args):
        calls.append(1)
        time.sleep(0.05)  # 放大并发窗口
        return original(*args)

    svc._compute = counting_compute
    results = []
    threads = [threading.Thread(target=lambda: results.append(svc.scan(RO, MANIFEST))) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(calls) == 1, f"expected single-flight, got {len(calls)} computations"
    assert len({id(r) for r in results}) == 1
    assert all(r.decision is Decision.ALLOW for r in results)


def test_rollback_invalidates_cache_and_recomputes():
    svc, reg, cache = make_service(
        Policy(version=1),
        Policy(version=2, denied_packages={"flask"}),
        publish=1,
    )
    assert svc.scan(RO, MANIFEST).decision is Decision.ALLOW
    reg.publish(PUB, 2)
    r = svc.scan(RO, MANIFEST)
    assert r.decision is Decision.DENY and r.policy_version == 2
    reg.rollback(PUB, 1)
    r = svc.scan(RO, MANIFEST)
    assert r.decision is Decision.ALLOW and r.policy_version == 1
    # 缓存中不应残留非当前版本的条目
    assert all(key[1] == 1 for key in cache._entries)


def test_scan_logs_hash_policy_version_and_rationale(caplog):
    svc, _, _ = make_service(Policy(version=3, denied_packages={"flask"}), publish=3)
    with caplog.at_level(logging.INFO, logger="scanner.service"):
        report = svc.scan(RO, MANIFEST)
    assert report.decision is Decision.DENY
    log_text = "\n".join(r.getMessage() for r in caplog.records)
    assert report.content_hash in log_text
    assert "policy_version=3" in log_text
    assert "decision=deny" in log_text
