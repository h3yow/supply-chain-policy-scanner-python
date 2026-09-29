"""Roles, policy register/publish/rollback and scan verdict reproducibility."""
from __future__ import annotations

import json

from conftest import DENY_LEFT_PAD, PUBLISHER, READER


def test_root_unchanged(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.json() == {"Hello": "World"}


def test_scan_requires_authentication(client):
    r = client.post("/api/v1/scan", json={"content": "x==1.0.0"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "authentication_required"
    r = client.post("/api/v1/scan", json={"content": "x==1.0.0"},
                    headers={"X-API-Key": "bogus"})
    assert r.status_code == 401


def test_reader_cannot_publish(client):
    r = client.post("/api/v1/policies", json=DENY_LEFT_PAD, headers=READER)
    assert r.status_code == 403
    err = r.json()["error"]
    assert err["code"] == "permission_denied"
    assert err["details"]["role"] == "reader"
    # publisher missing key -> 401, distinguishable from 403
    r2 = client.post("/api/v1/policies", json=DENY_LEFT_PAD)
    assert r2.status_code == 401


def test_register_publish_current_version_flow(client):
    r = client.post("/api/v1/policies", json=DENY_LEFT_PAD, headers=PUBLISHER)
    assert r.status_code == 201
    draft = r.json()["draft_id"]
    # drafts visible before publish
    listing = client.get("/api/v1/policies/versions", headers=READER).json()
    assert any(d["draft_id"] == draft for d in listing["drafts"])
    r = client.post(f"/api/v1/policies/{draft}/publish", headers=PUBLISHER)
    assert r.status_code == 200 and r.json()["policy_version"] == "v1"
    cur = client.get("/api/v1/policies/current", headers=READER).json()
    assert cur["policy_version"] == "v1" and cur["rule_count"] == 1


def test_publish_unknown_draft_404(client):
    r = client.post("/api/v1/policies/nope/publish", headers=PUBLISHER)
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "policy_not_found"


def test_invalid_policy_is_rejected_with_reason(client):
    bad = {"name": "p", "rules": [
        {"id": "r1", "effect": "deny", "package": "x", "version_range": ">=2,<1"}]}
    r = client.post("/api/v1/policies", json=bad, headers=PUBLISHER)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_policy"


def test_scan_deny_verdict_carries_policy_version_and_basis(client, published_policy):
    manifest = json.dumps({
        "dependencies": {"left-pad": "1.3.0", "lodash": "4.17.21"}})
    r = client.post("/api/v1/scan",
                    json={"content": manifest}, headers=READER)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["policy_version"] == "v1"
    assert body["decision"] == "fail"
    denied = [f for f in body["findings"] if f["code"] == "denied_package"]
    assert len(denied) == 1
    assert denied[0]["subject"].startswith("left-pad")
    assert "DENY-LEFT-PAD" in denied[0]["basis"]
    assert body["content_hash"] and len(body["content_hash"]) == 64


def test_same_content_same_policy_is_reproducible(client, published_policy):
    payload = {"content": "requests==2.31.0\n"}
    a = client.post("/api/v1/scan", json=payload, headers=READER).json()
    b = client.post("/api/v1/scan", json=payload, headers=READER).json()
    assert a == b
    assert a["policy_version"] == "v1"


def test_pin_nonexistent_policy_version_404(client, published_policy):
    r = client.post("/api/v1/scan",
                    json={"content": "requests==2.31.0", "policy_version": "v99"},
                    headers=READER)
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "policy_version_not_found"
