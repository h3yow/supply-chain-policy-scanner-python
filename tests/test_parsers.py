"""Malformed manifests: rejection reasons must be distinguishable."""
from __future__ import annotations

import json

import pytest

from scanner.errors import ManifestParseError, UnsupportedFormatError
from scanner.models import ParseRejectReason as R
from scanner.parsers.base import detect_format, parse_manifest


def test_requirements_distinct_reject_reasons():
    content = "\n".join([
        "requests==2.31.0",
        "urllib3>=2.0,<1.0",      # invalid (unsatisfiable) range
        "left-pad",               # missing version
        "-r other.txt",           # unsupported recursive include
        "pkg @ https://x/p.tgz",  # unsupported direct URL
        "==1.0.0",                # missing name
    ])
    m = parse_manifest(content)
    reasons = [x.reason for x in m.rejections]
    assert reasons == [
        R.INVALID_VERSION_RANGE,
        R.MISSING_VERSION,
        R.UNSUPPORTED_FIELD,
        R.UNSUPPORTED_FIELD,
        R.MISSING_NAME,
    ]
    # valid entry still present, nothing silently dropped
    assert [p.name for p in m.packages] == ["requests"]
    assert len(m.rejections) == 5


def test_package_json_distinct_reject_reasons():
    body = {
        "dependencies": {
            "ok": "1.2.3",
            "a": "^3.0.0",
            "bad-range": ">=9,<1",
            "url-pkg": "github:u/r",
            "wrong-type": 42,
        }
    }
    m = parse_manifest(json.dumps(body))
    reasons = sorted(x.reason.value for x in m.rejections)
    assert reasons == sorted([
        "invalid_version_range", "unsupported_field", "missing_version"])
    names = [p.name for p in m.packages]
    assert names == ["ok", "a"]


def test_package_lock_invalid_version_and_missing_fields():
    lock = {"lockfileVersion": 3, "packages": {
        "node_modules/good": {"version": "1.0.0"},
        "node_modules/badver": {"version": "not-a-version"},
        "node_modules/nover": {},
        "node_modules/shape": "nope",
    }}
    m = parse_manifest(json.dumps(lock))
    assert [p.name for p in m.packages] == ["good"]
    by_path = {x.raw: x.reason for x in m.rejections}
    assert by_path["node_modules/badver"] is R.INVALID_VERSION_RANGE
    assert by_path["node_modules/nover"] is R.MISSING_VERSION
    assert by_path["node_modules/shape"] is R.INCOMPLETE_STRUCTURE


def test_spdx_and_cyclonedx_rejections():
    spdx = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOC", "packages": [
        {"SPDXID": "SPDXRef-a", "name": "a", "versionInfo": "1.0.0",
         "purl": "pkg:npm/a@1.0.0"},
        {"SPDXID": "SPDXRef-b", "name": "b"},
        {"SPDXID": "SPDXRef-c", "name": "c", "versionInfo": "1.2.3-"},
        {"SPDXID": "SPDXRef-d", "name": "d", "versionInfo": "1",
         "purl": "pkg:maven/d@1"},
    ]}
    m = parse_manifest(json.dumps(spdx))
    reasons = sorted(x.reason.value for x in m.rejections)
    assert reasons == ["invalid_version_range", "missing_version",
                       "unsupported_field"]

    cdx = {"bomFormat": "CycloneDX", "components": [
        {"type": "library", "name": "a", "version": "1.0.0",
         "purl": "pkg:npm/a@1.0.0"},
        {"type": "library", "name": "b"},  # missing version
        {"name": "c", "version": "1.0.0", "purl": "pkg:npm/c@1.0.0"},  # no type
    ]}
    m = parse_manifest(json.dumps(cdx))
    assert [p.name for p in m.packages] == ["a"]
    assert [x.reason for x in m.rejections] == [
        R.MISSING_VERSION, R.INCOMPLETE_STRUCTURE]


def test_syntactically_broken_json_aborts_document():
    with pytest.raises(ManifestParseError) as exc:
        parse_manifest('{"dependencies": ')
    assert exc.value.code == "manifest_unparseable"


def test_unknown_format():
    with pytest.raises(UnsupportedFormatError) as exc:
        detect_format("nothing recognizable here")
    assert exc.value.code == "unsupported_format"


def test_content_hash_stable_and_present():
    a = parse_manifest("requests==2.31.0\n")
    b = parse_manifest("requests==2.31.0\n")
    assert a.content_hash == b.content_hash
    assert len(a.content_hash) == 64
