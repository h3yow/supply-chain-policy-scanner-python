"""Parser interface: format detection and dispatch."""
from __future__ import annotations

import json

from scanner.errors import ManifestParseError, UnsupportedFormatError
from scanner.hashing import content_hash
from scanner.models import ManifestFormat, NormalizedManifest
from scanner.parsers.npm_parser import parse_package_json, parse_package_lock
from scanner.parsers.requirements_parser import parse as parse_requirements
from scanner.parsers.sbom_parser import parse_cyclonedx, parse_spdx


def detect_format(content: str) -> ManifestFormat:
    """Sniff the format from content. Raises UnsupportedFormatError if unknown."""
    stripped = content.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # structurally JSON (starts with '{'), but unreadable: this is a
            # malformed document, not an unsupported format
            raise ManifestParseError("content looks like JSON but fails to parse")
        if isinstance(data, dict):
            if data.get("bomFormat") == "CycloneDX":
                return ManifestFormat.CYCLONEDX_JSON
            if "spdxVersion" in data:
                return ManifestFormat.SPDX_JSON
            if "lockfileVersion" in data or "packages" in data and isinstance(data.get("packages"), dict):
                return ManifestFormat.PACKAGE_LOCK_JSON
            if "dependencies" in data or "devDependencies" in data:
                return ManifestFormat.PACKAGE_JSON
        raise UnsupportedFormatError("unrecognized JSON manifest structure")
    # line-oriented pip requirements: first non-comment line must have a
    # PEP-508 style requirement token
    for line in stripped.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            if line.startswith("-") or any(
                    sep in line for sep in ("==", ">=", "<=", "~=", "@")):
                return ManifestFormat.REQUIREMENTS_TXT
            break
    raise UnsupportedFormatError("could not detect manifest format")


_PARSERS = {
    ManifestFormat.REQUIREMENTS_TXT: parse_requirements,
    ManifestFormat.PACKAGE_JSON: parse_package_json,
    ManifestFormat.PACKAGE_LOCK_JSON: parse_package_lock,
    ManifestFormat.SPDX_JSON: parse_spdx,
    ManifestFormat.CYCLONEDX_JSON: parse_cyclonedx,
}


def parse_manifest(
    content: str, declared: ManifestFormat = ManifestFormat.AUTO
) -> NormalizedManifest:
    fmt = detect_format(content) if declared is ManifestFormat.AUTO else declared
    parser = _PARSERS.get(fmt)
    if parser is None:
        raise UnsupportedFormatError(f"unsupported format: {fmt}")
    return parser(content, content_hash(content))
