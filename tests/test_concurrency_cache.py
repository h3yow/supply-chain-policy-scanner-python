"""Concurrent identical content scans compute once; policy changes recompute."""
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor

from conftest import PUBLISHER, READER


def test_concurrent_identical_content_computed_once(client, published_policy):
    """12 concurrent HTTP requests for identical content: identical verdicts and
    a single cache entry; the underlying parse runs exactly once."""
    import scanner.service as svc_mod
    service = client.app.state.service
    real_parse = svc_mod.parse_manifest
    count = {"n": 0}
    started = threading.Event()
    hold = threading.Event()

    def counting_parse(content, fmt):
        count["n"] += 1
        started.set()
        hold.wait(2.0)
        return real_parse(content, fmt)

    svc_mod.parse_manifest = counting_parse  # type: ignore[assignment]
    try:
        payload = {"content": "requests==2.31.0\nflask==3.0.0\n"}
        results: list = []
        errors: list = []

        def hit():
            try:
                r = client.post("/api/v1/scan", json=payload, headers=READER)
                results.append((r.status_code, r.json()))
            except BaseException as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=hit) for _ in range(12)]
        for t in threads:
            t.start()
        assert started.wait(2.0), "parse never started"
        hold.set()
        for t in threads:
            t.join()

        assert not errors
        assert count["n"] == 1, count
        assert all(status == 200 for status, _ in results)
        bodies = [body for _, body in results]
        assert all(body == bodies[0] for body in bodies)
        assert service._cache.size() == 1
        assert all(body["policy_version"] == "v1" for body in bodies)
    finally:
        svc_mod.parse_manifest = real_parse  # type: ignore[assignment]


def test_cache_returns_same_object_for_repeat_scan(client, published_policy):
    service = client.app.state.service
    content = "requests==2.31.0\n"
    r1 = service.scan(content)
    assert service._cache.size() == 1
    r2 = service.scan(content)
    assert r1 is r2


def test_publish_invalidates_cache_and_recomputes(client, published_policy):
    service = client.app.state.service
    content = json.dumps({"dependencies": {"lodash": "4.17.21"}})
    before = service.scan(content)
    assert before.policy_version == "v1" and before.decision.value == "pass"
    assert service._cache.size() == 1

    new_policy = {"name": "stricter", "default_effect": "deny", "rules": []}
    r = client.post("/api/v1/policies", json=new_policy, headers=PUBLISHER)
    draft = r.json()["draft_id"]
    client.post(f"/api/v1/policies/{draft}/publish", headers=PUBLISHER)
    assert service._cache.size() == 0

    after = service.scan(content)
    assert after.policy_version == "v2"
    assert after.decision.value == "fail"
    assert after != before


def test_rollback_recomputes_under_new_version_label(client, published_policy):
    service = client.app.state.service
    content = json.dumps({"dependencies": {"left-pad": "1.3.0"}})
    v1 = service.scan(content)
    assert v1.decision.value == "fail" and v1.policy_version == "v1"

    r = client.post("/api/v1/policies",
                    json={"name": "open", "default_effect": "allow", "rules": []},
                    headers=PUBLISHER)
    client.post(f"/api/v1/policies/{r.json()['draft_id']}/publish",
                headers=PUBLISHER)
    v2 = service.scan(content)
    assert v2.policy_version == "v2" and v2.decision.value == "pass"

    r = client.post("/api/v1/policies/rollback",
                    json={"version": "v1"}, headers=PUBLISHER)
    assert r.status_code == 200 and r.json()["policy_version"] == "v3"
    v3 = service.scan(content)
    assert v3.policy_version == "v3"
    assert v3.decision.value == "fail"
    assert v3.content_hash == v1.content_hash
    assert v3.findings == v1.findings


def test_pinned_historical_version_still_scannable(client, published_policy):
    service = client.app.state.service
    content = json.dumps({"dependencies": {"left-pad": "1.3.0"}})
    r = client.post("/api/v1/policies",
                    json={"name": "open", "default_effect": "allow", "rules": []},
                    headers=PUBLISHER)
    client.post(f"/api/v1/policies/{r.json()['draft_id']}/publish",
                headers=PUBLISHER)
    client.post("/api/v1/policies/rollback", json={"version": "v1"},
                headers=PUBLISHER)
    v2_pinned = service.scan(content, policy_version="v2")
    assert v2_pinned.policy_version == "v2"
    assert v2_pinned.decision.value == "pass"
    assert service.scan(content).policy_version == "v3"
