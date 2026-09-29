"""供应链策略合规扫描服务 HTTP 接口。"""
from __future__ import annotations

import logging
from dataclasses import asdict

import uvicorn
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from scanner.models import AuthError, Policy, Role
from scanner.policy import (
    REASON_NO_ACTIVE_POLICY,
    REASON_VERSION_EXISTS,
    REASON_VERSION_NOT_FOUND,
    REASON_VERSION_NOT_PUBLISHED,
    PolicyError,
    PolicyRegistry,
)
from scanner.service import ScanService

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

_ERROR_STATUS = {
    AuthError.MISSING_TOKEN.value: 401,
    AuthError.UNKNOWN_TOKEN.value: 401,
    AuthError.FORBIDDEN_ROLE.value: 403,
    REASON_VERSION_NOT_FOUND: 404,
    REASON_VERSION_EXISTS: 409,
    REASON_VERSION_NOT_PUBLISHED: 409,
    REASON_NO_ACTIVE_POLICY: 409,
}


def _token(authorization: str | None) -> str | None:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return authorization


class PolicyIn(BaseModel):
    version: int
    denied_packages: list[str] = []
    denied_licenses: list[str] = []
    allow_prerelease: bool = False


def _policy_out(policy: Policy) -> dict:
    return {
        "version": policy.version,
        "denied_packages": sorted(policy.denied_packages),
        "denied_licenses": sorted(policy.denied_licenses),
        "allow_prerelease": policy.allow_prerelease,
        "published": policy.published,
    }


def create_app(registry: PolicyRegistry | None = None) -> FastAPI:
    """构建应用实例；测试可注入独立 registry 保证隔离。"""
    registry = registry or PolicyRegistry()
    service = ScanService(registry)
    app = FastAPI(title="supply-chain-policy-scanner")
    app.state.registry = registry
    app.state.service = service

    @app.exception_handler(PolicyError)
    async def policy_error_handler(_: Request, exc: PolicyError) -> JSONResponse:
        status = _ERROR_STATUS.get(exc.reason, 400)
        return JSONResponse(status_code=status, content={"error": exc.reason, "detail": exc.detail})

    @app.get("/")
    def read_root():
        return {"Hello": "World"}

    @app.post("/policies", status_code=201)
    def register_policy(body: PolicyIn, authorization: str | None = Header(default=None)):
        policy = Policy(
            version=body.version,
            denied_packages=frozenset(body.denied_packages),
            denied_licenses=frozenset(body.denied_licenses),
            allow_prerelease=body.allow_prerelease,
        )
        return _policy_out(registry.register(_token(authorization), policy))

    @app.post("/policies/{version}/publish")
    def publish_policy(version: int, authorization: str | None = Header(default=None)):
        return _policy_out(registry.publish(_token(authorization), version))

    @app.post("/policies/{version}/rollback")
    def rollback_policy(version: int, authorization: str | None = Header(default=None)):
        return _policy_out(registry.rollback(_token(authorization), version))

    @app.get("/policies/current")
    def current_policy(authorization: str | None = Header(default=None)):
        return _policy_out(registry.current(authorization and _token(authorization)))

    @app.post("/scan")
    async def scan(request: Request, authorization: str | None = Header(default=None)):
        content = await request.body()
        report = service.scan(_token(authorization), content)
        return asdict(report)

    return app


app = create_app()


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
