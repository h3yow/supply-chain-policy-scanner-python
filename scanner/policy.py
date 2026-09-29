"""策略登记、发布、回滚与角色鉴权。"""
from __future__ import annotations

import logging
import threading

from .models import AuthError, Policy, Role

logger = logging.getLogger("scanner.policy")

# 内置账号：本地服务使用静态 token -> 角色映射
DEFAULT_TOKENS: dict[str, Role] = {
    "readonly-token": Role.READONLY,
    "publisher-token": Role.PUBLISHER,
}


class PolicyError(Exception):
    """策略操作失败，携带可区分原因（AuthError 值或策略状态原因）。"""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail


REASON_VERSION_EXISTS = "version_exists"
REASON_VERSION_NOT_FOUND = "version_not_found"
REASON_VERSION_NOT_PUBLISHED = "version_not_published"
REASON_NO_ACTIVE_POLICY = "no_active_policy"


class PolicyRegistry:
    """策略注册表：草稿登记、发布、回滚；线程安全。"""

    def __init__(self, tokens: dict[str, Role] | None = None) -> None:
        self._tokens = dict(DEFAULT_TOKENS if tokens is None else tokens)
        self._policies: dict[int, Policy] = {}
        self._active_version: int | None = None
        self._lock = threading.RLock()
        self._listeners: list = []

    def add_listener(self, listener) -> None:
        """订阅发布 / 回滚事件，回调签名为 (event: str, version: int)。"""
        with self._lock:
            self._listeners.append(listener)

    def _notify(self, event: str, version: int) -> None:
        with self._lock:
            listeners = list(self._listeners)
        for listener in listeners:
            listener(event, version)

    def authenticate(self, token: str | None) -> Role:
        """校验 token 并返回角色，失败抛 PolicyError（AuthError 原因）。"""
        if token is None or not token:
            raise PolicyError(AuthError.MISSING_TOKEN.value, "authentication token is required")
        role = self._tokens.get(token)
        if role is None:
            raise PolicyError(AuthError.UNKNOWN_TOKEN.value, "token is not recognized")
        return role

    def _require_publisher(self, token: str | None) -> None:
        role = self.authenticate(token)
        if role is not Role.PUBLISHER:
            raise PolicyError(AuthError.FORBIDDEN_ROLE.value, f"role {role.value} cannot modify policies")

    def register(self, token: str | None, policy: Policy) -> Policy:
        """登记新策略草稿（需要发布角色）。版本号不可重复。"""
        self._require_publisher(token)
        with self._lock:
            if policy.version in self._policies:
                raise PolicyError(REASON_VERSION_EXISTS, f"policy version {policy.version} already registered")
            draft = Policy(
                version=policy.version,
                denied_packages=frozenset(policy.denied_packages),
                denied_licenses=frozenset(policy.denied_licenses),
                allow_prerelease=policy.allow_prerelease,
                published=False,
            )
            self._policies[draft.version] = draft
            logger.info("policy registered: version=%d", draft.version)
            return draft

    def publish(self, token: str | None, version: int) -> Policy:
        """发布指定版本为当前生效策略（需要发布角色）。"""
        self._require_publisher(token)
        with self._lock:
            policy = self._policies.get(version)
            if policy is None:
                raise PolicyError(REASON_VERSION_NOT_FOUND, f"policy version {version} not registered")
            published = Policy(
                version=policy.version,
                denied_packages=policy.denied_packages,
                denied_licenses=policy.denied_licenses,
                allow_prerelease=policy.allow_prerelease,
                published=True,
            )
            self._policies[version] = published
            previous = self._active_version
            self._active_version = version
            logger.info("policy published: version=%d (previous=%s)", version, previous)
        self._notify("publish", version)
        return published

    def rollback(self, token: str | None, version: int) -> Policy:
        """回滚到历史已发布版本（需要发布角色）。"""
        self._require_publisher(token)
        with self._lock:
            policy = self._policies.get(version)
            if policy is None:
                raise PolicyError(REASON_VERSION_NOT_FOUND, f"policy version {version} not registered")
            if not policy.published:
                raise PolicyError(REASON_VERSION_NOT_PUBLISHED, f"policy version {version} was never published")
            previous = self._active_version
            self._active_version = version
            logger.info("policy rolled back: version=%d (previous=%s)", version, previous)
        self._notify("rollback", version)
        return policy

    def current(self, token: str | None) -> Policy:
        """获取当前生效策略（只读角色即可）。"""
        self.authenticate(token)
        with self._lock:
            if self._active_version is None:
                raise PolicyError(REASON_NO_ACTIVE_POLICY, "no policy has been published yet")
            return self._policies[self._active_version]

