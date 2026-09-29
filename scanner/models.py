"""核心数据模型：清单条目、解析结果、策略、判定结论。"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


class ManifestFormat(enum.Enum):
    """支持的清单 / SBOM 格式。"""

    REQUIREMENTS_TXT = "requirements_txt"
    PACKAGE_JSON = "package_json"
    CYCLONEDX_JSON = "cyclonedx_json"


class RejectReason(enum.Enum):
    """条目级 / 文件级拒绝原因，必须可区分。"""

    EMPTY_CONTENT = "empty_content"
    UNKNOWN_FORMAT = "unknown_format"
    MALFORMED_DOCUMENT = "malformed_document"
    MISSING_NAME = "missing_name"
    MISSING_VERSION = "missing_version"
    INVALID_VERSION_SPEC = "invalid_version_spec"
    INVALID_STRUCTURE = "invalid_structure"


class Role(enum.Enum):
    """调用方角色。"""

    READONLY = "readonly"
    PUBLISHER = "publisher"


class AuthError(enum.Enum):
    """越权原因，必须可区分。"""

    MISSING_TOKEN = "missing_token"
    UNKNOWN_TOKEN = "unknown_token"
    FORBIDDEN_ROLE = "forbidden_role"


class IssueKind(enum.Enum):
    """依赖图问题类型。"""

    CYCLE = "cycle"
    DUPLICATE = "duplicate"
    VERSION_CONFLICT = "version_conflict"


class Decision(enum.Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class Dependency:
    """归一化后的依赖条目。spec 为原始版本约束字符串，depends_on 为直接依赖名。"""

    name: str
    spec: str
    depends_on: tuple[str, ...] = ()
    license: str = ""


@dataclass(frozen=True)
class ParseError:
    """单条解析失败记录。"""

    reason: RejectReason
    detail: str
    location: str = ""


@dataclass
class ParseResult:
    """解析结果：成功的依赖列表 + 拒绝记录。任一拒绝都使扫描失败。"""

    format: ManifestFormat | None = None
    dependencies: list[Dependency] = field(default_factory=list)
    errors: list[ParseError] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


@dataclass(frozen=True)
class GraphIssue:
    kind: IssueKind
    detail: str
    packages: tuple[str, ...] = ()


@dataclass
class Policy:
    """策略版本。deny 列表命中即拒绝；allow_prerelease 控制预发布版本。"""

    version: int
    denied_packages: frozenset[str] = frozenset()
    denied_licenses: frozenset[str] = frozenset()
    allow_prerelease: bool = False
    published: bool = False


@dataclass(frozen=True)
class VerdictItem:
    """单个依赖的判定依据。"""

    name: str
    spec: str
    decision: Decision
    reason: str


@dataclass
class ScanReport:
    """扫描结论：整体判定 + 逐项依据 + 图问题 + 策略版本 + 内容哈希。"""

    content_hash: str
    policy_version: int
    decision: Decision
    items: list[VerdictItem] = field(default_factory=list)
    issues: list[GraphIssue] = field(default_factory=list)
    errors: list[ParseError] = field(default_factory=list)
