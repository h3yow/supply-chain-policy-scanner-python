"""Parsers for SPDX 2.3 JSON and CycloneDX 1.4/1.5 JSON SBOMs."""
from __future__ import annotations

import json

from scanner.errors import ManifestParseError
from scanner.models import (
    Ecosystem,
    ManifestFormat,
    NormalizedManifest,
    Package,
    ParseRejection,
    ParseRejectReason,
)
from scanner.versions import InvalidVersionRange, parse_version

_SPDX_REF_PREFIX = "SPDXRef-"


def _load_object(content: str, kind: str) -> dict:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ManifestParseError(f"invalid {kind} JSON: {exc.msg} at line {exc.lineno}") from exc
    if not isinstance(data, dict):
        raise ManifestParseError(f"{kind} root must be an object")
    return data


def _spdx_ecosym(purl: str) -> tuple[Ecosystem, str]:
    """Extract (ecosystem, canonical name) from a package URL."""
    rest = purl[len("pkg:"):]
    ecosystem_part, _, loc = rest.partition("/")
    ecosystem = {"npm": Ecosystem.NPM, "pypi": Ecosystem.PYPI}.get(
        ecosystem_part.lower(), Ecosystem.UNKNOWN)
    name = loc.split("?", 1)[0].split("@", 1)[0]
    return ecosystem, name.lower()


def parse_spdx(content: str, content_hash: str) -> NormalizedManifest:
    data = _load_object(content, "SPDX")
    if "spdxVersion" not in data or "SPDXID" not in data:
        raise ManifestParseError("not an SPDX document: missing spdxVersion/SPDXID")
    packages_raw = data.get("packages")
    if packages_raw is None:
        raise ManifestParseError("SPDX document missing packages array")
    if not isinstance(packages_raw, list):
        raise ManifestParseError("SPDX packages must be an array")

    packages: list[Package] = []
    rejections: list[ParseRejection] = []
    id_to_name: dict[str, str] = {}
    idx = 0
    for entry in packages_raw:
        if not isinstance(entry, dict):
            rejections.append(ParseRejection(
                ParseRejectReason.MALFORMED_ENTRY, idx, str(entry)[:80],
                "package entry must be an object"))
            idx += 1
            continue
        spdxid = entry.get("SPDXID", "")
        name = entry.get("name")
        version_info = entry.get("versionInfo")
        purl = entry.get("purl", "") or _external_ref_purl(entry.get("externalRefs"))
        if not name:
            rejections.append(ParseRejection(
                ParseRejectReason.MISSING_NAME, idx, json.dumps(entry)[:80],
                "package missing name"))
            idx += 1
            continue
        if not version_info:
            rejections.append(ParseRejection(
                ParseRejectReason.MISSING_VERSION, idx, str(spdxid or name),
                f"package {name!r} missing versionInfo"))
            idx += 1
            continue
        try:
            version = parse_version(str(version_info)).raw
        except InvalidVersionRange as exc:
            rejections.append(ParseRejection(
                ParseRejectReason.INVALID_VERSION_RANGE, idx,
                f"{name}@{version_info}", str(exc)))
            idx += 1
            continue
        if not purl:
            rejections.append(ParseRejection(
                ParseRejectReason.INCOMPLETE_STRUCTURE, idx, str(spdxid or name),
                "package missing purl/externalRef (ecosystem unknown)"))
            idx += 1
            continue
        ecosystem, cname = _spdx_ecosym(purl)
        if ecosystem is Ecosystem.UNKNOWN:
            rejections.append(ParseRejection(
                ParseRejectReason.UNSUPPORTED_FIELD, idx, purl,
                "unsupported ecosystem in purl"))
            idx += 1
            continue
        if spdxid:
            id_to_name[spdxid] = cname
        packages.append(Package(
            cname, version, ecosystem, f"spdx:{spdxid or name}", f"=={version}"))
        idx += 1

    edges: list[tuple[str, str]] = []
    for rel in data.get("relationships", []) or []:
        if not isinstance(rel, dict):
            continue
        if rel.get("relationshipType") == "DEPENDS_ON":
            src = id_to_name.get(rel.get("spdxElementId", ""))
            dst = id_to_name.get(rel.get("relatedSpdxElement", ""))
            if src and dst:
                edges.append((src, dst))

    return NormalizedManifest(
        ManifestFormat.SPDX_JSON, content_hash,
        tuple(packages), tuple(edges), tuple(rejections))


def _external_ref_purl(refs) -> str:
    if not isinstance(refs, list):
        return ""
    for ref in refs:
        if isinstance(ref, dict) and ref.get("referenceType") == "purl":
            return str(ref.get("referenceLocator", ""))
    return ""


def parse_cyclonedx(content: str, content_hash: str) -> NormalizedManifest:
    data = _load_object(content, "CycloneDX")
    if data.get("bomFormat") != "CycloneDX":
        raise ManifestParseError("not a CycloneDX document: missing bomFormat")
    components = data.get("components")
    if components is None:
        raise ManifestParseError("CycloneDX document missing components array")
    if not isinstance(components, list):
        raise ManifestParseError("components must be an array")

    valid_types = {"library", "framework", "application", "container", "device",
                   "firmware", "file", "machine-learning-model", "operating-system"}
    packages: list[Package] = []
    rejections: list[ParseRejection] = []
    ref_to_name: dict[str, str] = {}
    idx = 0
    for entry in components:
        if not isinstance(entry, dict):
            rejections.append(ParseRejection(
                ParseRejectReason.MALFORMED_ENTRY, idx, str(entry)[:80],
                "component must be an object"))
            idx += 1
            continue
        if entry.get("type") not in valid_types:
            rejections.append(ParseRejection(
                ParseRejectReason.INCOMPLETE_STRUCTURE, idx,
                str(entry.get("bom-ref", "")), "invalid/missing component type"))
            idx += 1
            continue
        name = entry.get("name")
        if not name:
            rejections.append(ParseRejection(
                ParseRejectReason.MISSING_NAME, idx,
                str(entry.get("bom-ref", "")), "component missing name"))
            idx += 1
            continue
        purl = str(entry.get("purl", ""))
        version = entry.get("version")
        if not version:
            rejections.append(ParseRejection(
                ParseRejectReason.MISSING_VERSION, idx, str(name),
                f"component {name!r} missing version"))
            idx += 1
            continue
        try:
            ver = parse_version(str(version)).raw
        except InvalidVersionRange as exc:
            rejections.append(ParseRejection(
                ParseRejectReason.INVALID_VERSION_RANGE, idx,
                f"{name}@{version}", str(exc)))
            idx += 1
            continue
        if purl.startswith("pkg:"):
            ecosystem, cname = _spdx_ecosym(purl)
        else:
            ecosystem, cname = Ecosystem.UNKNOWN, str(name).lower()
        if ecosystem is Ecosystem.UNKNOWN:
            rejections.append(ParseRejection(
                ParseRejectReason.UNSUPPORTED_FIELD, idx,
                str(entry.get("bom-ref", name)),
                "unsupported/missing ecosystem (purl required)"))
            idx += 1
            continue
        ref = str(entry.get("bom-ref", ""))
        if ref:
            ref_to_name[ref] = cname
        packages.append(Package(
            cname, ver, ecosystem, f"cyclonedx:{ref or cname}", f"=={ver}"))
        idx += 1

    edges: list[tuple[str, str]] = []
    for rel in data.get("dependencies", []) or []:
        if not isinstance(rel, dict):
            continue
        src = ref_to_name.get(str(rel.get("ref", "")))
        if not src:
            continue
        for target in rel.get("dependsOn", []) or []:
            dst = ref_to_name.get(str(target))
            if dst:
                edges.append((src, dst))

    return NormalizedManifest(
        ManifestFormat.CYCLONEDX_JSON, content_hash,
        tuple(packages), tuple(edges), tuple(rejections))
