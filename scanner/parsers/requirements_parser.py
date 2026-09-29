"""Parser for pip ``requirements.txt`` style manifests.

Rejected entries are never silently dropped: every problematic line produces
a :class:`ParseRejection` with a distinguishable reason.
"""
from __future__ import annotations

import re

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
    is_concrete_version,
    parse_version,
    validate_range,
)

_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_DIRECT_URL_RE = re.compile(r"^(https?|git\+https?|git@|file|ftp)://", re.IGNORECASE)
_KNOWN_INLINE_OPTIONS = {"--hash", "--config-settings", "--global-option"}
_UNSUPPORTED_OPTIONS = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable",
    "-f", "--find-links", "--index-url", "-i", "--extra-index-url",
    "--no-index", "--pre", "--use-feature",
}


def _canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _rej(reason: ParseRejectReason, index: int, raw: str, detail: str) -> ParseRejection:
    return ParseRejection(reason, index, raw, detail)


def parse(content: str, content_hash: str) -> NormalizedManifest:
    packages: list[Package] = []
    rejections: list[ParseRejection] = []

    for index, raw_line in enumerate(content.splitlines()):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.split(" #", 1)[0].strip()  # trailing comments
        line = line.split(";", 1)[0].strip()   # environment markers

        tokens = line.split()
        # Drop known inline options regardless of position
        # (``pkg==1 --hash=...`` or ``--hash=... pkg==1``).
        tokens = [t for t in tokens if not any(
            t == opt or t.startswith(opt + "=") for opt in _KNOWN_INLINE_OPTIONS
        )]
        if not tokens:
            continue
        if tokens[0] in _UNSUPPORTED_OPTIONS or tokens[0].startswith("-"):
            rejections.append(_rej(
                ParseRejectReason.UNSUPPORTED_FIELD, index, raw_line,
                f"unsupported requirements option or recursive include: {tokens[0]}"))
            continue
        line = " ".join(tokens)

        if "@" in line:
            name_part = line.split("@", 1)[0].strip()
            reason = (ParseRejectReason.UNSUPPORTED_FIELD if _NAME_RE.match(name_part)
                      else ParseRejectReason.MALFORMED_ENTRY)
            detail = ("direct URL/VCS install without pinned version"
                      if reason is ParseRejectReason.UNSUPPORTED_FIELD
                      else "direct URL install without package name")
            rejections.append(_rej(reason, index, raw_line, detail))
            continue
        if _DIRECT_URL_RE.match(line) or line in (".", "./"):
            rejections.append(_rej(
                ParseRejectReason.MALFORMED_ENTRY, index, raw_line,
                "URL/path install without package name"))
            continue

        m = _NAME_RE.match(line)
        if not m:
            if line.startswith(("=", "!", ">", "<", "~", "^")):
                rejections.append(_rej(
                    ParseRejectReason.MISSING_NAME, index, raw_line,
                    "version specifier without a package name"))
            else:
                rejections.append(_rej(
                    ParseRejectReason.MALFORMED_ENTRY, index, raw_line,
                    "could not parse requirement name"))
            continue
        name = m.group(1)
        rest = line[m.end():].strip()
        if rest.startswith("["):  # extras
            close = rest.find("]")
            if close == -1:
                rejections.append(_rej(
                    ParseRejectReason.MALFORMED_ENTRY, index, raw_line,
                    "unclosed extras group"))
                continue
            rest = rest[close + 1:].strip()
        spec = rest.replace(" ", "")
        if not spec:
            rejections.append(_rej(
                ParseRejectReason.MISSING_VERSION, index, raw_line,
                f"package {name!r} has no version specifier"))
            continue
        if not spec.startswith(("=", "!", ">", "<", "~", "^")):
            rejections.append(_rej(
                ParseRejectReason.MALFORMED_ENTRY, index, raw_line,
                f"unparseable version specifier: {spec!r}"))
            continue
        try:
            validate_range(spec)
        except InvalidVersionRange as exc:
            rejections.append(_rej(
                ParseRejectReason.INVALID_VERSION_RANGE, index, raw_line, str(exc)))
            continue

        cname = _canonical_name(name)
        source = f"requirements.txt:L{index + 1}"
        if is_concrete_version(spec):
            version = parse_version(spec.lstrip("=")).raw
            packages.append(Package(cname, version, Ecosystem.PYPI, source, spec))
        else:
            packages.append(Package(cname, "", Ecosystem.PYPI, source, spec))

    return NormalizedManifest(
        ManifestFormat.REQUIREMENTS_TXT, content_hash,
        tuple(packages), (), tuple(rejections),
    )
