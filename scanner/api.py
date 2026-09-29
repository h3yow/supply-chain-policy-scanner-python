"""FastAPI router: scan endpoint and policy administration."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, Field

from scanner.models import ManifestFormat
from scanner.policy.models import document_from_dict
from scanner.policy.roles import ROLE_PUBLISHER, ROLE_READER, RoleAuthorizer
from scanner.service import result_to_dict

router = APIRouter(prefix="/api/v1")


# --- request/response schemas -------------------------------------------------

class ScanRequest(BaseModel):
    content: str = Field(..., description="Raw manifest / SBOM text")
    format: ManifestFormat = ManifestFormat.AUTO
    policy_version: str | None = Field(
        default=None, description="Pin a specific policy version; defaults to current")


class RegisterPolicyRequest(BaseModel):
    name: str
    description: str = ""
    default_effect: str = "allow"
    rules: list[dict] = Field(default_factory=list)


class RollbackRequest(BaseModel):
    version: str


# --- singletons ---------------------------------------------------------------

def get_authorizer(request: Request) -> RoleAuthorizer:
    return request.app.state.authorizer


def get_service(request: Request):
    return request.app.state.service


def require_reader(
    request: Request,
    x_api_key: str | None = Header(default=None),
) -> str:
    authorizer: RoleAuthorizer = request.app.state.authorizer
    return authorizer.require_role(x_api_key, ROLE_READER)


def require_publisher(
    request: Request,
    x_api_key: str | None = Header(default=None),
) -> str:
    authorizer: RoleAuthorizer = request.app.state.authorizer
    return authorizer.require_role(x_api_key, ROLE_PUBLISHER)


# --- scan ---------------------------------------------------------------------

@router.post("/scan", tags=["scan"])
def scan_endpoint(
    body: ScanRequest,
    request: Request,
    role: str = Depends(require_reader),
):
    service = request.app.state.service
    result = service.scan(body.content, body.format, body.policy_version)
    return result_to_dict(result)


# --- policy administration ----------------------------------------------------

@router.post("/policies", tags=["policies"], status_code=201)
def register_policy(
    body: RegisterPolicyRequest,
    request: Request,
    role: str = Depends(require_publisher),
):
    service = request.app.state.service
    document = document_from_dict(body.model_dump())
    draft_id = service.store.register(document, actor_role=role)
    return {"draft_id": draft_id, "status": "registered_draft"}


@router.post("/policies/{draft_id}/publish", tags=["policies"])
def publish_policy(
    draft_id: str,
    request: Request,
    role: str = Depends(require_publisher),
):
    service = request.app.state.service
    version = service.store.publish(draft_id, actor_role=role)
    return {"policy_version": version, "status": "published"}


@router.post("/policies/rollback", tags=["policies"])
def rollback_policy(
    body: RollbackRequest,
    request: Request,
    role: str = Depends(require_publisher),
):
    service = request.app.state.service
    version = service.store.rollback(body.version, actor_role=role)
    return {"policy_version": version, "rolled_back_from": body.version,
            "status": "rolled_back"}


@router.get("/policies/current", tags=["policies"])
def current_policy(
    request: Request,
    role: str = Depends(require_reader),
):
    service = request.app.state.service
    label, doc = service.store.current()
    return {"policy_version": label, "name": doc.name,
            "default_effect": doc.default_effect.value,
            "rule_count": len(doc.rules)}


@router.get("/policies/versions", tags=["policies"])
def list_versions(
    request: Request,
    role: str = Depends(require_reader),
):
    service = request.app.state.service
    return {"versions": service.store.list_versions(),
            "drafts": service.store.list_drafts()}
