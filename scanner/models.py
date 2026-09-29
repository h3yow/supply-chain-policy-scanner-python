"""Domain models shared across parsing, policy and scanning."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ManifestFormat(str, Enum):
    """Supported dependency manifest / SBOM formats."""

    REQUIREMENTS_TXT = "requirements.txt"
    PACKAGE_JSON = "package.json"
    PACKAGE_LOCK_JSON = "package-lock.json"
    SPDX_JSON = "spdx-json"
    CYCLONEDX_JSON = "cyclonedx-json"
    AUTO = "auto"


class Ecosystem(str, Enum):
    PYPI = "pypi"
    NPM = "npm"
    UNKNOWN = "unknown"


class ParseRejectReason(str, Enum):
    """Distinguishable reasons an individual entry is rejected."""

    MISSING_NAME = "missing_name"
    MISSING_VERSION = "missing_version"
    INVALID_VERSION_RANGE = "invalid_version_range"
    MALFORMED_ENTRY = "malformed_entry"
    INCOMPLETE_STRUCTURE = "incomplete_structure"
    UNSUPPORTED_FIELD = "unsupported_field"


class FindingCode(str, Enum):
    DENIED_PACKAGE = "denied_package"
    ALLOWED_PACKAGE = "allowed_package"
    UNKNOWN_PACKAGE = "unknown_package"
    DUPLICATE_INTRODUCTION = "duplicate_introduction"
    VERSION_CONFLICT = "version_conflict"
    CIRCULAR_DEPENDENCY = "circular_dependency"
    ENTRY_REJECTED = "entry_rejected"


class Decision(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True)
class Package:
    """A normalized dependency entry."""

    name: str
    version: str
    ecosystem: Ecosystem
    introduced_by: str = ""
    version_range: str = ""
    dependencies: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ParseRejection:
    reason: ParseRejectReason
    index: int
    raw: str
    detail: str


@dataclass(frozen=True)
class NormalizedManifest:
    format: ManifestFormat
    content_hash: str
    packages: tuple[Package, ...]
    edges: tuple[tuple[str, str], ...]
    rejections: tuple[ParseRejection, ...]


@dataclass(frozen=True)
class Finding:
    code: FindingCode
    decision: Decision
    subject: str
    detail: str
    basis: str


@dataclass(frozen=True)
class ScanResult:
    content_hash: str
    policy_version: str
    decision: Decision
    findings: tuple[Finding, ...]
    package_count: int
    rejected_count: int
