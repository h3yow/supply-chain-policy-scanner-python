"""Cycles / duplicates / conflicts are marked; malformed manifests error 422
with distinguishable reasons, not silent skips."""
from __future__ import annotations

import json

from conftest import READER


def test_circular_dependency_marked(client, published_policy):
    lock = {"lockfileVersion": 3, "packages": {
        "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "2.0.0"}},
        "node_modules/b": {"version": "2.0.0", "dependencies": {"c": "3.0.0"}},
        "node_modules/c": {"version": "3.0.0", "dependencies": {"a": "1.0.0"}},
        "node_modules/self": {"version": "1.0.0",
                              "dependencies": {"self": "1.0.0"}},
    }}
    r = client.post("/api/v1/scan", json={"content": json.dumps(lock)},
                    headers=READER)
    # parse rejections exist? no - all valid; structural findings still FAIL
    assert r.status_code == 200
    findings = r.json()["findings"]
    cycles = {f["subject"]: f for f in findings
              if f["code"] == "circular_dependency"}
    assert set(cycles) == {"a", "b", "c", "self"}
    assert all(f["decision"] == "fail" for f in cycles.values())
    assert "a -> b -> c -> a" in cycles["a"]["basis"]


def test_version_conflict_marked_not_silently_chosen(client, published_policy):
    lock = {"lockfileVersion": 3, "packages": {
        "node_modules/x/a": {"name": "a", "version": "1.0.0"},
        "node_modules/y/a": {"name": "a", "version": "2.0.0"},
    }}
    r = client.post("/api/v1/scan", json={"content": json.dumps(lock)},
                    headers=READER)
    assert r.status_code == 200
    conflicts = [f for f in r.json()["findings"]
                 if f["code"] == "version_conflict"]
    assert len(conflicts) == 1
    assert conflicts[0]["subject"] == "a"
    assert "1.0.0" in conflicts[0]["detail"] and "2.0.0" in conflicts[0]["detail"]


def test_duplicate_introduction_marked(client, published_policy):
    lock = {"lockfileVersion": 3, "packages": {
        "node_modules/x/a": {"name": "a", "version": "1.0.0"},
        "node_modules/y/a": {"name": "a", "version": "1.0.0"},
    }}
    r = client.post("/api/v1/scan", json={"content": json.dumps(lock)},
                    headers=READER)
    body = r.json()
    dups = [f for f in body["findings"] if f["code"] == "duplicate_introduction"]
    assert len(dups) == 1
    assert dups[0]["decision"] == "warn"
    assert "node_modules/x/a" in dups[0]["basis"]


def test_malformed_manifest_returns_422_with_distinct_reasons(client, published_policy):
    content = "ok==1.0.0\nurllib3>=2.0,<1.0\nnokey\n"
    r = client.post("/api/v1/scan", json={"content": content}, headers=READER)
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "manifest_rejected"
    reasons = [x["reason"] for x in err["details"]["rejections"]]
    assert reasons == ["invalid_version_range", "missing_version"]
    # the embedded partial result is still reproducible and versioned
    partial = err["details"]["result"]
    assert partial["policy_version"] == "v1"
    assert partial["content_hash"]
    assert len(err["details"]["rejections"][0]["detail"]) > 0


def test_broken_json_returns_manifest_unparseable(client, published_policy):
    r = client.post("/api/v1/scan", json={"content": "{not json"}, headers=READER)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "manifest_unparseable"


def test_unsupported_format_415(client, published_policy):
    r = client.post("/api/v1/scan", json={"content": "???"}, headers=READER)
    assert r.status_code == 415
    assert r.json()["error"]["code"] == "unsupported_format"
