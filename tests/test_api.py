import threading

import pytest
from fastapi.testclient import TestClient

from main import create_app
from scanner.policy import PolicyRegistry

PUB = {"Authorization": "Bearer publisher-token"}
RO = {"Authorization": "Bearer readonly-token"}


@pytest.fixture()
def client():
    return TestClient(create_app(PolicyRegistry()))


def publish_v1(client, denied=None):
    assert client.post("/policies", json={"version": 1, "denied_packages": denied or []}, headers=PUB).status_code == 201
    assert client.post("/policies/1/publish", headers=PUB).status_code == 200


def test_existing_root_endpoint_unchanged(client):
    assert client.get("/").json() == {"Hello": "World"}


def test_scan_requires_token_and_distinguishes_reasons(client):
    r = client.post("/scan", content=b"flask>=2.0")
    assert r.status_code == 401 and r.json()["error"] == "missing_token"
    r = client.post("/scan", content=b"flask>=2.0", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401 and r.json()["error"] == "unknown_token"


def test_readonly_cannot_publish_and_reason_distinguishable(client):
    r = client.post("/policies", json={"version": 1}, headers=RO)
    assert r.status_code == 403 and r.json()["error"] == "forbidden_role"
    r = client.post("/policies/1/publish", headers=RO)
    assert r.status_code == 403 and r.json()["error"] == "forbidden_role"


def test_policy_state_errors_distinguishable(client):
    publish_v1(client)
    r = client.post("/policies", json={"version": 1}, headers=PUB)
    assert r.status_code == 409 and r.json()["error"] == "version_exists"
    r = client.post("/policies/99/publish", headers=PUB)
    assert r.status_code == 404 and r.json()["error"] == "version_not_found"
    r = client.post("/policies", json={"version": 2}, headers=PUB)
    r = client.post("/policies/2/rollback", headers=PUB)
    assert r.status_code == 409 and r.json()["error"] == "version_not_published"


def test_scan_report_carries_hash_and_policy_version(client):
    publish_v1(client, denied=["evil"])
    r = client.post("/scan", content=b"flask>=2.0\nevil==1.0\n", headers=RO)
    body = r.json()
    assert r.status_code == 200
    assert body["decision"] == "deny"
    assert body["policy_version"] == 1
    assert len(body["content_hash"]) == 64
    denied = [i for i in body["items"] if i["decision"] == "deny"]
    assert denied and "policy v1" in denied[0]["reason"]


def test_malformed_manifest_reasons_distinguishable(client):
    publish_v1(client)
    cases = [
        (b"", "empty_content"),
        (b"\xff\xfe\x00binary", "unknown_format"),
        (b"{not json", "unknown_format"),
        (b'{"dependencies": {"a": null}}', "missing_version"),
        (b'{"dependencies": {"a": ">=abc"}}', "invalid_version_spec"),
        (b'{"bomFormat": "CycloneDX"}', "invalid_structure"),
        (b'{"dependencies": [1,2]}', "invalid_structure"),
    ]
    for content, expected in cases:
        r = client.post("/scan", content=content, headers=RO)
        body = r.json()
        assert body["decision"] == "deny", (content, body)
        reasons = {e["reason"] for e in body["errors"]}
        assert expected in reasons, (content, reasons)


def test_same_manifest_reproducible_under_same_policy_version(client):
    publish_v1(client)
    r1 = client.post("/scan", content=b"flask>=2.0\n", headers=RO).json()
    r2 = client.post("/scan", content=b"flask>=2.0\n", headers=RO).json()
    assert r1 == r2 and r1["policy_version"] == 1


def test_rollback_recomputes_and_report_shows_active_version(client):
    publish_v1(client)
    client.post("/policies", json={"version": 2, "denied_packages": ["flask"]}, headers=PUB)
    client.post("/policies/2/publish", headers=PUB)
    assert client.post("/scan", content=b"flask>=2.0\n", headers=RO).json()["decision"] == "deny"
    client.post("/policies/1/rollback", headers=PUB)
    body = client.post("/scan", content=b"flask>=2.0\n", headers=RO).json()
    assert body["decision"] == "allow" and body["policy_version"] == 1


def test_concurrent_identical_scans_consistent(client):
    publish_v1(client)
    results = []

    def work():
        results.append(client.post("/scan", content=b"flask>=2.0\nrequests==2.31.0\n", headers=RO).json())

    threads = [threading.Thread(target=work) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 16
    first = results[0]
    assert all(r == first for r in results)
