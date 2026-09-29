import pytest

from scanner.models import AuthError, Policy
from scanner.policy import (
    REASON_NO_ACTIVE_POLICY,
    REASON_VERSION_EXISTS,
    REASON_VERSION_NOT_FOUND,
    REASON_VERSION_NOT_PUBLISHED,
    PolicyError,
    PolicyRegistry,
)

PUB = "publisher-token"
RO = "readonly-token"


def make_registry():
    return PolicyRegistry()


def test_missing_token():
    with pytest.raises(PolicyError) as exc:
        make_registry().current(None)
    assert exc.value.reason == AuthError.MISSING_TOKEN.value


def test_unknown_token():
    with pytest.raises(PolicyError) as exc:
        make_registry().current("nope")
    assert exc.value.reason == AuthError.UNKNOWN_TOKEN.value


def test_readonly_cannot_register_publish_or_rollback():
    reg = make_registry()
    reg.register(PUB, Policy(version=1))
    for op in (
        lambda: reg.register(RO, Policy(version=2)),
        lambda: reg.publish(RO, 1),
        lambda: reg.rollback(RO, 1),
    ):
        with pytest.raises(PolicyError) as exc:
            op()
        assert exc.value.reason == AuthError.FORBIDDEN_ROLE.value


def test_register_duplicate_version_rejected():
    reg = make_registry()
    reg.register(PUB, Policy(version=1))
    with pytest.raises(PolicyError) as exc:
        reg.register(PUB, Policy(version=1))
    assert exc.value.reason == REASON_VERSION_EXISTS


def test_publish_unknown_version():
    with pytest.raises(PolicyError) as exc:
        make_registry().publish(PUB, 42)
    assert exc.value.reason == REASON_VERSION_NOT_FOUND


def test_current_without_publish():
    reg = make_registry()
    reg.register(PUB, Policy(version=1))
    with pytest.raises(PolicyError) as exc:
        reg.current(RO)
    assert exc.value.reason == REASON_NO_ACTIVE_POLICY


def test_rollback_requires_previously_published_version():
    reg = make_registry()
    reg.register(PUB, Policy(version=1))
    reg.register(PUB, Policy(version=2))
    reg.publish(PUB, 1)
    with pytest.raises(PolicyError) as exc:
        reg.rollback(PUB, 2)  # v2 从未发布过
    assert exc.value.reason == REASON_VERSION_NOT_PUBLISHED


def test_publish_then_rollback_switches_active_version():
    reg = make_registry()
    reg.register(PUB, Policy(version=1, denied_packages={"a"}))
    reg.register(PUB, Policy(version=2, denied_packages={"b"}))
    reg.publish(PUB, 1)
    reg.publish(PUB, 2)
    assert reg.current(RO).version == 2
    reg.rollback(PUB, 1)
    current = reg.current(RO)
    assert current.version == 1 and current.denied_packages == {"a"}


def test_listener_notified_on_publish_and_rollback():
    reg = make_registry()
    events = []
    reg.add_listener(lambda e, v: events.append((e, v)))
    reg.register(PUB, Policy(version=1))
    reg.publish(PUB, 1)
    reg.rollback(PUB, 1)
    assert events == [("publish", 1), ("rollback", 1)]
