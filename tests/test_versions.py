import pytest

from scanner.versions import InvalidVersionSpec, intersects, parse_spec, parse_version


def test_parse_plain_version():
    v = parse_version("1.2.3")
    assert v.release == (1, 2, 3) and v.prerelease == ""


def test_parse_prerelease():
    v = parse_version("2.0.0-rc1")
    assert v.prerelease == "rc1"


@pytest.mark.parametrize("bad", ["", "abc", "1..2", ">=1.0", "1.0-"])
def test_invalid_version_rejected(bad):
    with pytest.raises(InvalidVersionSpec):
        parse_version(bad)


@pytest.mark.parametrize("spec,version,expected", [
    ("*", "0.0.1", True),
    ("1.2.3", "1.2.3", True),
    ("1.2.3", "1.2.4", False),
    (">=1.0,<2.0", "1.5", True),
    (">=1.0,<2.0", "2.0", False),
    ("^1.2.3", "1.9.9", True),
    ("^1.2.3", "2.0.0", False),
    ("^0.2.3", "0.2.9", True),
    ("^0.2.3", "0.3.0", False),
    ("~1.2.3", "1.2.9", True),
    ("~1.2.3", "1.3.0", False),
    ("==1.2.*", "1.2.7", True),
    ("==1.2.*", "1.3.0", False),
    ("!=1.5", "1.5", False),
    ("~=1.4.5", "1.4.9", True),
    ("~=1.4.5", "1.5.0", False),
])
def test_spec_contains(spec, version, expected):
    assert parse_spec(spec).contains(parse_version(version)) is expected


@pytest.mark.parametrize("bad", [">=abc", "1.0,", "><1.0", "~=x"])
def test_invalid_spec_rejected(bad):
    with pytest.raises(InvalidVersionSpec):
        parse_spec(bad)


def test_intersects():
    assert intersects(parse_spec(">=1.0,<2.0"), parse_spec(">=1.5"))
    assert not intersects(parse_spec(">=2.0"), parse_spec("<2.0"))
    assert intersects(parse_spec("*"), parse_spec("1.2.3"))
