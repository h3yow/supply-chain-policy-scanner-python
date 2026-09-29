"""Parsers for npm ``package.json`` and ``package-lock.json`` (v2/v3).

Malformed JSON aborts the whole document (``ManifestParseError``); individual
bad entries are collected as distinguishable :class:`ParseRejection`s.
"""
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
from scanner.versions import (
    InvalidVersionRange,
    parse_constraints,
    parse_version,
)

_DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")


def _npm_name(name: str) -> str:
    return name.strip().lower()


def _make_package(name: str, spec: str, source: str) -> tuple[Package | None, ParseRejection | None]:
    if not name or not isinstance(name, str):
        return None, ParseRejection(ParseRejectReason.MISSING_NAME, -1, str(name), "entry missing name")
    if not isinstance(spec, str) or not spec.strip():
        return None, ParseRejection(ParseRejectReason.MISSING_VERSION, -1,
                                    f"{name}@{spec}", f"entry {name!r} missing version specifier")
    spec = spec.strip()
    # npm aliases, VCS/URL/file/workspace refs and moving targets are not
    # reproducible registry versions, so reject them with a distinct reason.
    if (spec.startswith(("git+", "http://", "https://", "github:", "file:",
                         "npm:", "workspace:")) or spec in ("*", "latest")):
        return None, ParseRejection(
            ParseRejectReason.UNSUPPORTED_FIELD, -1, f"{name}@{spec}",
            f"non-registry or non-pinned version specifier: {spec!r}")
    try:
        cs = parse_constraints(spec)
    except InvalidVersionRange as exc:
        return None, ParseRejection(
            ParseRejectReason.INVALID_VERSION_RANGE, -1, f"{name}@{spec}", str(exc))
    cname = _npm_name(name)
    concrete = (len(cs) == 1 and cs[0].op == "==" and cs[0].version is not None)
    if concrete:
        return Package(cname, parse_version(cs[0].version.raw).raw,
                       Ecosystem.NPM, source, spec), None
    return Package(cname, "", Ecosystem.NPM, source, spec), None


def parse_package_json(content: str, content_hash: str) -> NormalizedManifest:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ManifestParseError(f"invalid JSON: {exc.msg} at line {exc.lineno}") from exc
    if not isinstance(data, dict):
        raise ManifestParseError("package.json root must be an object")

    packages: list[Package] = []
    rejections: list[ParseRejection] = []
    idx = 0
    for section in _DEP_SECTIONS:
        block = data.get(section)
        if block is None:
            continue
        if not isinstance(block, dict):
            rejections.append(ParseRejection(
                ParseRejectReason.INCOMPLETE_STRUCTURE, idx,
                f'"{section}": {type(block).__name__}',
                f"{section} must be an object"))
            continue
        for name, spec in block.items():
            pkg, rej = _make_package(str(name), spec if isinstance(spec, str) else "",
                                     f"package.json#{section}")
            if rej:
                rejections.append(ParseRejection(rej.reason, idx, rej.raw, rej.detail))
            else:
                assert pkg is not None
                packages.append(pkg)
            idx += 1
    return NormalizedManifest(
        ManifestFormat.PACKAGE_JSON, content_hash,
        tuple(packages), (), tuple(rejections))


def parse_package_lock(content: str, content_hash: str) -> NormalizedManifest:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ManifestParseError(f"invalid JSON: {exc.msg} at line {exc.lineno}") from exc
    if not isinstance(data, dict) or "packages" not in data:
        raise ManifestParseError(
            "package-lock.json must be an object with a packages map (lockfileVersion 2/3)")
    packages_map = data["packages"]
    if not isinstance(packages_map, dict):
        raise ManifestParseError("packages must be an object")

    packages: list[Package] = []
    rejections: list[ParseRejection] = []
    edges: list[tuple[str, str]] = []
    idx = 0
    for path, info in packages_map.items():
        if path == "":
            continue  # project root
        if not isinstance(info, dict):
            rejections.append(ParseRejection(
                ParseRejectReason.INCOMPLETE_STRUCTURE, idx, path,
                "package entry must be an object"))
            idx += 1
            continue
        if info.get("link") or info.get("inBundle"):
            rejections.append(ParseRejection(
                ParseRejectReason.UNSUPPORTED_FIELD, idx, path,
                "linked/bundled package is not a registry entry"))
            idx += 1
            continue
        name = info.get("name") or path.split("node_modules/")[-1]
        version = info.get("version")
        if not name:
            rejections.append(ParseRejection(
                ParseRejectReason.MISSING_NAME, idx, path, "entry missing name"))
            idx += 1
            continue
        if not version:
            rejections.append(ParseRejection(
                ParseRejectReason.MISSING_VERSION, idx, path,
                f"entry {name!r} missing resolved version"))
            idx += 1
            continue
        if not isinstance(version, str):
            rejections.append(ParseRejection(
                ParseRejectReason.MALFORMED_ENTRY, idx, path,
                f"version must be a string: {version!r}"))
            idx += 1
            continue
        try:
            parsed = parse_version(version)
        except InvalidVersionRange as exc:
            rejections.append(ParseRejection(
                ParseRejectReason.INVALID_VERSION_RANGE, idx, path, str(exc)))
            idx += 1
            continue
        cname = _npm_name(str(name))
        source = f"package-lock.json#{path or '<root>'}"
        pkg = Package(cname, parsed.raw, Ecosystem.NPM, source, f"=={parsed.raw}")
        packages.append(pkg)
        for dep in info.get("dependencies", {}) or {}:
            edges.append((cname, _npm_name(str(dep))))
        idx += 1
    return NormalizedManifest(
        ManifestFormat.PACKAGE_LOCK_JSON, content_hash,
        tuple(packages), tuple(edges), tuple(rejections))
