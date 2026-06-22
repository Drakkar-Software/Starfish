"""Tests for the space-access store (module-level singleton).

Each test calls ``clear_space_access_store()`` in setup to ensure isolation.
"""

from __future__ import annotations

import pytest
from tests.helpers import MemoryKvAdapter

from starfish_spaces.space_access_store import (
    clear_space_access_store,
    configure_space_access_store,
    get_node_access_entry,
    get_node_keyring_access_entry,
    get_node_stream_access_entry,
    get_space_access_entry,
    remove_node_access_entry,
    remove_space_access_entry,
    save_node_access_entry,
    save_node_keyring_access_entry,
    save_node_stream_access_entry,
    save_space_access_entry,
    local_space_access_entries,
)

SPACE = "sp-test"
NODE = "obj-node"
USER = "user1"


@pytest.fixture(autouse=True)
def reset():
    """Reset the singleton store before each test."""
    clear_space_access_store()
    yield
    clear_space_access_store()


def test_save_and_get_space_entry():
    save_space_access_entry(SPACE, {"kind": "member", "cap": '{"sub": "abc"}'})
    entry = get_space_access_entry(SPACE)
    assert entry is not None
    assert entry.get("kind") == "member"


def test_missing_space_entry():
    assert get_space_access_entry("unknown") is None


def test_remove_space_entry():
    save_space_access_entry(SPACE, {"kind": "member", "cap": "x"})
    remove_space_access_entry(SPACE)
    assert get_space_access_entry(SPACE) is None


def test_save_and_get_node_entry():
    save_node_access_entry(SPACE, NODE, {"kind": "member", "cap": "nodecap"})
    entry = get_node_access_entry(SPACE, NODE)
    assert entry is not None
    assert entry.get("kind") == "member"


def test_node_stream_entry():
    save_node_stream_access_entry(SPACE, NODE, {"kind": "link", "cap": "sc", "key": "kk"})
    e = get_node_stream_access_entry(SPACE, NODE)
    assert e is not None
    assert e.get("kind") == "link"


def test_node_keyring_entry():
    save_node_keyring_access_entry(SPACE, NODE, {"kind": "member", "cap": "krc"})
    e = get_node_keyring_access_entry(SPACE, NODE)
    assert e is not None
    assert e.get("cap") == "krc"


def test_remove_node_entry_removes_all_tiers():
    save_node_access_entry(SPACE, NODE, {"kind": "member", "cap": "c"})
    save_node_stream_access_entry(SPACE, NODE, {"kind": "member", "cap": "s"})
    save_node_keyring_access_entry(SPACE, NODE, {"kind": "member", "cap": "k"})
    remove_node_access_entry(SPACE, NODE)
    assert get_node_access_entry(SPACE, NODE) is None
    assert get_node_stream_access_entry(SPACE, NODE) is None
    assert get_node_keyring_access_entry(SPACE, NODE) is None


def test_kv_key_prefix_is_octospaces():
    """The KV key prefix must match the cross-language constant."""
    from starfish_spaces.space_access_store import _kv_key_prefix  # type: ignore[attr-defined]
    assert _kv_key_prefix.startswith("octospaces.spaceaccess.")


def test_local_entries():
    save_space_access_entry("sp1", {"kind": "member", "cap": "c1"})
    save_space_access_entry("sp2", {"kind": "link", "cap": "c2", "key": "k"})
    entries = local_space_access_entries()
    space_ids = {sid for sid, _ in entries}
    assert "sp1" in space_ids
    assert "sp2" in space_ids


def test_configure_store_with_kv():
    kv = MemoryKvAdapter()
    configure_space_access_store(USER, kv, "octospaces.spaceaccess.")
    # No error
