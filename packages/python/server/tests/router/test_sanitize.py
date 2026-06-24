"""Tests for deep_sanitize — verifies the full 5-key UNSAFE_KEYS denylist.

The TS server sources UNSAFE_KEYS from the protocol package (5 keys:
__proto__, constructor, prototype, __class__, __dict__). The Python server
must strip the same set so both languages produce identical content hashes for
the same document. A divergent denylist breaks cross-language deployments:
a TS-signed element that strips __class__/__dict__ is rejected as an invalid
author signature by a Python server that retained them (and vice-versa).
"""

import pytest

from starfish_server.router.helpers import deep_sanitize
from starfish_protocol.merge import UNSAFE_KEYS


# ---------------------------------------------------------------------------
# UNSAFE_KEYS denylist parity
# ---------------------------------------------------------------------------


def test_unsafe_keys_contains_all_five():
    """The protocol-shared set must include both JS-pollution and Python-dunder keys."""
    required = {"__proto__", "constructor", "prototype", "__class__", "__dict__"}
    assert required <= UNSAFE_KEYS, (
        f"UNSAFE_KEYS is missing: {required - UNSAFE_KEYS!r}. "
        "The Python and TS server must strip an identical set of keys so "
        "cross-language document hashes agree."
    )


# ---------------------------------------------------------------------------
# deep_sanitize strips all five unsafe keys at top level
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", sorted(UNSAFE_KEYS))
def test_deep_sanitize_removes_unsafe_key_at_top_level(key):
    body = {"safe": 1, key: "evil"}
    result = deep_sanitize(body)
    assert key not in result, f"deep_sanitize should have stripped key {key!r}"
    assert result == {"safe": 1}


# ---------------------------------------------------------------------------
# deep_sanitize strips unsafe keys at arbitrary depth
# ---------------------------------------------------------------------------


def test_deep_sanitize_removes_class_and_dict_nested():
    """__class__ and __dict__ (the previously-missing two) must be stripped recursively."""
    body = {
        "level1": {
            "__class__": "bad",
            "__dict__": {"secret": "value"},
            "safe_nested": {
                "__proto__": "x",
                "ok": True,
            },
        }
    }
    result = deep_sanitize(body)
    assert result == {"level1": {"safe_nested": {"ok": True}}}


def test_deep_sanitize_preserves_safe_keys():
    body = {"name": "alice", "age": 30, "data": {"value": 42}}
    assert deep_sanitize(body) == body


def test_deep_sanitize_strips_constructor_and_prototype():
    body = {"constructor": "malicious", "prototype": {"is_admin": True}, "real": "data"}
    result = deep_sanitize(body)
    assert result == {"real": "data"}


# ---------------------------------------------------------------------------
# Cross-language hash parity: same doc → same stable_stringify after sanitize
# ---------------------------------------------------------------------------


def test_sanitize_then_hash_matches_ts_expectation():
    """A doc with __class__/__dict__ must hash the same as its safe counterpart.

    The TS server strips both keys before hashing; after this fix the Python
    server does too, so both sides produce the same canonical string.
    """
    from starfish_protocol.hash import compute_hash

    # Document with unsafe keys that both TS and Python should strip
    raw = {"value": 1, "__class__": "evil", "__dict__": {"x": 2}}
    sanitized = deep_sanitize(raw)

    # After sanitization the doc is {"value": 1}
    expected_hash = compute_hash({"value": 1})
    assert compute_hash(sanitized) == expected_hash
