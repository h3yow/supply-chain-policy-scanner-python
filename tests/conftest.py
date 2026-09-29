"""Shared fixtures: a fresh app and publisher-seeded policy for each test."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from main import app
from scanner.config import RoleConfig
from scanner.policy.roles import RoleAuthorizer

READER = {"X-API-Key": "reader-local-key"}
PUBLISHER = {"X-API-Key": "publisher-local-key"}

DENY_LEFT_PAD = {
    "name": "default",
    "default_effect": "allow",
    "rules": [
        {"id": "DENY-LEFT-PAD", "effect": "deny", "ecosystem": "npm",
         "package": "left-pad", "version_range": "<2.0.0",
         "reason": "known malicious package"},
    ],
}


@pytest.fixture
def client() -> TestClient:
    # Rebuild service state for full isolation between tests.
    from scanner.service import ScannerService
    service = ScannerService(authorizer=RoleAuthorizer(RoleConfig(
        frozenset({"reader-local-key"}), frozenset({"publisher-local-key"}))))
    app.state.service = service
    return TestClient(app)


@pytest.fixture
def published_policy(client: TestClient) -> str:
    r = client.post("/api/v1/policies", json=DENY_LEFT_PAD, headers=PUBLISHER)
    assert r.status_code == 201, r.text
    draft_id = r.json()["draft_id"]
    r = client.post(f"/api/v1/policies/{draft_id}/publish", headers=PUBLISHER)
    assert r.status_code == 200, r.text
    return r.json()["policy_version"]
