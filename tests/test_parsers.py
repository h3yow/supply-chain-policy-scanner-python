import json

from scanner.models import ManifestFormat, RejectReason
from scanner.parsers import detect_format, parse_manifest


def reasons(result):
    return {e.reason for e in result.errors}


def test_requirements_txt_ok():
    r = parse_manifest(b"flask>=2.0\nrequests==2.31.0\n# comment\n\n")
    assert r.ok and r.format is ManifestFormat.REQUIREMENTS_TXT
    assert [(d.name, d.spec) for d in r.dependencies] == [("flask", ">=2.0"), ("requests", "==2.31.0")]


def test_requirements_txt_missing_version():
    r = parse_manifest(b"flask\n")
    assert not r.ok
    assert reasons(r) == {RejectReason.MISSING_VERSION}
    assert r.errors[0].location == "line 1"


def test_requirements_txt_invalid_spec():
    r = parse_manifest(b"flask>=abc\n")
    assert reasons(r) == {RejectReason.INVALID_VERSION_SPEC}


def test_package_json_ok():
    doc = {"name": "demo", "dependencies": {"react": "^18.2.0"}, "devDependencies": {"vitest": "~1.0.0"}}
    r = parse_manifest(json.dumps(doc).encode())
    assert r.ok and r.format is ManifestFormat.PACKAGE_JSON
    assert {d.name for d in r.dependencies} == {"react", "vitest"}


def test_package_json_malformed_json():
    r = parse_manifest(b'{"dependencies": {"a": "1.0"', ManifestFormat.PACKAGE_JSON)
    assert reasons(r) == {RejectReason.MALFORMED_DOCUMENT}


def test_package_json_no_dependency_sections():
    r = parse_manifest(b'{"name": "demo"}')
    assert reasons(r) == {RejectReason.INVALID_STRUCTURE}


def test_package_json_entry_errors_are_distinguishable():
    doc = {"dependencies": {"a": ">=abc", "b": None, "c": 123}}
    r = parse_manifest(json.dumps(doc).encode())
    assert reasons(r) == {RejectReason.INVALID_VERSION_SPEC, RejectReason.MISSING_VERSION}
    by_loc = {e.location: e.reason for e in r.errors}
    assert by_loc["dependencies.b"] is RejectReason.MISSING_VERSION
    assert by_loc["dependencies.c"] is RejectReason.INVALID_VERSION_SPEC


def test_cyclonedx_ok_with_edges_and_license():
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"name": "a", "version": "1.0.0", "licenses": [{"license": {"id": "Apache-2.0"}}]},
            {"name": "b", "version": "2.0.0"},
        ],
        "dependencies": [{"ref": "a@1.0.0", "dependsOn": ["b@2.0.0"]}],
    }
    r = parse_manifest(json.dumps(doc).encode())
    assert r.ok and r.format is ManifestFormat.CYCLONEDX_JSON
    a = next(d for d in r.dependencies if d.name == "a")
    assert a.depends_on == ("b",) and a.license == "Apache-2.0"


def test_cyclonedx_missing_components_array():
    r = parse_manifest(b'{"bomFormat": "CycloneDX"}')
    assert reasons(r) == {RejectReason.INVALID_STRUCTURE}


def test_cyclonedx_component_missing_fields():
    doc = {"bomFormat": "CycloneDX", "components": [{"version": "1.0"}, {"name": "x"}, "junk"]}
    r = parse_manifest(json.dumps(doc).encode())
    assert RejectReason.MISSING_NAME in reasons(r)
    assert RejectReason.MISSING_VERSION in reasons(r)
    assert RejectReason.INVALID_STRUCTURE in reasons(r)


def test_empty_content():
    assert reasons(parse_manifest(b"")) == {RejectReason.EMPTY_CONTENT}
    assert reasons(parse_manifest(b"   \n ")) == {RejectReason.EMPTY_CONTENT}


def test_unknown_format():
    assert reasons(parse_manifest(b"\xff\xfe\x00\x01binary")) == {RejectReason.UNKNOWN_FORMAT}


def test_detect_format_dispatch():
    assert detect_format(b"flask>=2.0") is ManifestFormat.REQUIREMENTS_TXT
    assert detect_format(b'{"dependencies": {}}') is ManifestFormat.PACKAGE_JSON
    assert detect_format(b'{"bomFormat": "CycloneDX", "components": []}') is ManifestFormat.CYCLONEDX_JSON
    assert detect_format(b"") is None
