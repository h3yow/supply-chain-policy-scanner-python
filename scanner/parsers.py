"""清单 / SBOM 解析与归一化。"""
from __future__ import annotations

import json
import re

from .models import Dependency, ManifestFormat, ParseError, ParseResult, RejectReason
from .versions import InvalidVersionSpec, parse_spec

_REQ_LINE_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*(.*)$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+(@[A-Za-z0-9_.\-]+)?$")


def detect_format(content: bytes) -> ManifestFormat | None:
    """根据内容嗅探格式，无法识别返回 None。"""
    stripped = content.strip()
    if not stripped:
        return None
    if stripped.startswith(b"{"):
        try:
            doc = json.loads(stripped)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if not isinstance(doc, dict):
            return None
        if doc.get("bomFormat") == "CycloneDX" or "components" in doc and "specVersion" in doc:
            return ManifestFormat.CYCLONEDX_JSON
        if "dependencies" in doc or "devDependencies" in doc or "name" in doc:
            return ManifestFormat.PACKAGE_JSON
        return None
    # 非 JSON 文本按 requirements.txt 处理（至少一行形如 name[spec]）
    try:
        text = stripped.decode("utf-8")
    except UnicodeDecodeError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return ManifestFormat.REQUIREMENTS_TXT if _REQ_LINE_RE.match(line) else None
    return None


def parse_manifest(content: bytes, fmt: ManifestFormat | None = None) -> ParseResult:
    """解析清单内容并归一化为 ParseResult。任何条目问题都记录为可区分的拒绝原因。"""
    if not content or not content.strip():
        return ParseResult(errors=[ParseError(RejectReason.EMPTY_CONTENT, "manifest content is empty")])
    if fmt is None:
        fmt = detect_format(content)
    if fmt is None:
        return ParseResult(errors=[ParseError(RejectReason.UNKNOWN_FORMAT, "cannot detect manifest format")])
    if fmt is ManifestFormat.REQUIREMENTS_TXT:
        return _parse_requirements(content)
    if fmt is ManifestFormat.PACKAGE_JSON:
        return _parse_package_json(content)
    if fmt is ManifestFormat.CYCLONEDX_JSON:
        return _parse_cyclonedx(content)
    return ParseResult(errors=[ParseError(RejectReason.UNKNOWN_FORMAT, f"unsupported format: {fmt}")])


def _validate_entry(result: ParseResult, name: object, spec: object, location: str) -> None:
    """校验单条依赖，合法则追加到 result.dependencies，否则记录拒绝原因。"""
    if not isinstance(name, str) or not name.strip():
        result.errors.append(ParseError(RejectReason.MISSING_NAME, f"dependency name missing or not a string", location))
        return
    name = name.strip()
    if spec is None or (isinstance(spec, str) and not spec.strip()):
        result.errors.append(ParseError(RejectReason.MISSING_VERSION, f"dependency {name!r} has no version spec", location))
        return
    if not isinstance(spec, str):
        result.errors.append(ParseError(RejectReason.INVALID_VERSION_SPEC, f"dependency {name!r} spec is not a string", location))
        return
    spec = spec.strip()
    try:
        parse_spec(spec)
    except InvalidVersionSpec as exc:
        result.errors.append(ParseError(RejectReason.INVALID_VERSION_SPEC, f"dependency {name!r}: {exc}", location))
        return
    result.dependencies.append(Dependency(name=name, spec=spec))


def _parse_requirements(content: bytes) -> ParseResult:
    result = ParseResult(format=ManifestFormat.REQUIREMENTS_TXT)
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        result.errors.append(ParseError(RejectReason.MALFORMED_DOCUMENT, f"not valid utf-8: {exc}"))
        return result
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        loc = f"line {lineno}"
        m = _REQ_LINE_RE.match(line)
        if not m:
            result.errors.append(ParseError(RejectReason.MALFORMED_DOCUMENT, f"unparseable requirement line: {line!r}", loc))
            continue
        name, spec = m.group(1), m.group(2).strip()
        if spec.startswith("(") and spec.endswith(")"):
            spec = spec[1:-1].strip()
        _validate_entry(result, name, spec or None, loc)
    return result


def _load_json(content: bytes, result: ParseResult) -> object | None:
    try:
        return json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        result.errors.append(ParseError(RejectReason.MALFORMED_DOCUMENT, f"invalid JSON: {exc}"))
        return None


def _parse_package_json(content: bytes) -> ParseResult:
    result = ParseResult(format=ManifestFormat.PACKAGE_JSON)
    doc = _load_json(content, result)
    if doc is None:
        return result
    if not isinstance(doc, dict):
        result.errors.append(ParseError(RejectReason.INVALID_STRUCTURE, "package.json root must be an object"))
        return result
    sections = [s for s in ("dependencies", "devDependencies") if s in doc]
    if not sections:
        result.errors.append(ParseError(RejectReason.INVALID_STRUCTURE, "package.json has no dependencies sections"))
        return result
    for section in sections:
        deps = doc[section]
        if not isinstance(deps, dict):
            result.errors.append(ParseError(RejectReason.INVALID_STRUCTURE, f"section {section!r} must be an object", section))
            continue
        for name, spec in deps.items():
            _validate_entry(result, name, spec, f"{section}.{name}")
    return result


def _parse_cyclonedx(content: bytes) -> ParseResult:
    result = ParseResult(format=ManifestFormat.CYCLONEDX_JSON)
    doc = _load_json(content, result)
    if doc is None:
        return result
    if not isinstance(doc, dict) or not isinstance(doc.get("components"), list):
        result.errors.append(ParseError(RejectReason.INVALID_STRUCTURE, "CycloneDX document must have a 'components' array"))
        return result
    for idx, comp in enumerate(doc["components"]):
        loc = f"components[{idx}]"
        if not isinstance(comp, dict):
            result.errors.append(ParseError(RejectReason.INVALID_STRUCTURE, "component must be an object", loc))
            continue
        before = len(result.dependencies)
        _validate_entry(result, comp.get("name"), comp.get("version"), loc)
        if len(result.dependencies) > before:
            lic = _cyclonedx_license(comp)
            if lic:
                dep = result.dependencies[-1]
                result.dependencies[-1] = Dependency(dep.name, dep.spec, dep.depends_on, lic)
    _attach_cyclonedx_edges(doc, result)
    return result


def _cyclonedx_license(comp: dict) -> str:
    """提取组件许可证标识（取第一个 license 的 id 或 name）。"""
    licenses = comp.get("licenses")
    if not isinstance(licenses, list) or not licenses:
        return ""
    first = licenses[0]
    if isinstance(first, dict):
        lic = first.get("license")
        if isinstance(lic, dict):
            return str(lic.get("id") or lic.get("name") or "")
        if isinstance(lic, str):
            return lic
    return ""


def _attach_cyclonedx_edges(doc: dict, result: ParseResult) -> None:
    """读取 CycloneDX dependencies 段，把 bom-ref 边映射为依赖名并写回条目。"""
    edges = doc.get("dependencies")
    if edges is None:
        return
    if not isinstance(edges, list):
        result.errors.append(ParseError(RejectReason.INVALID_STRUCTURE, "'dependencies' must be an array", "dependencies"))
        return
    # bom-ref -> 组件名；缺省 bom-ref 按 name@version 处理
    ref_to_name: dict[str, str] = {}
    for comp, dep in zip(doc["components"], result.dependencies):
        if isinstance(comp, dict):
            ref = comp.get("bom-ref") or f"{dep.name}@{dep.spec}"
            ref_to_name[ref] = dep.name
    by_name = {d.name: d for d in result.dependencies}
    extra: list[Dependency] = []
    for idx, entry in enumerate(edges):
        loc = f"dependencies[{idx}]"
        if not isinstance(entry, dict) or not isinstance(entry.get("ref"), str):
            result.errors.append(ParseError(RejectReason.INVALID_STRUCTURE, "dependency entry must have a string 'ref'", loc))
            continue
        src_name = ref_to_name.get(entry["ref"])
        targets = entry.get("dependsOn", [])
        if not isinstance(targets, list):
            result.errors.append(ParseError(RejectReason.INVALID_STRUCTURE, "'dependsOn' must be an array", loc))
            continue
        names = tuple(ref_to_name[t] for t in targets if isinstance(t, str) and t in ref_to_name)
        if src_name is None:
            # 引用未知组件： dangling ref，记为结构问题
            result.errors.append(ParseError(RejectReason.INVALID_STRUCTURE, f"unknown bom-ref {entry['ref']!r}", loc))
            continue
        dep = by_name[src_name]
        merged = Dependency(dep.name, dep.spec, tuple(dict.fromkeys(dep.depends_on + names)), dep.license)
        by_name[src_name] = merged
    result.dependencies = [by_name[d.name] for d in result.dependencies]
