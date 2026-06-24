"""Tests for default_space_layout path + scope methods."""

from __future__ import annotations

import json
import pathlib

import pytest

from starfish_spaces.layout import default_space_layout

_VECTOR_PATH = (
    pathlib.Path(__file__).parents[4] / "tests" / "test-vectors" / "spaces-layout.json"
)

SPACE_ID = "sp-test123"
NODE_ID = "obj-node456"
USER_ID = "abcd1234abcd1234abcd1234abcd1234"
SHARD = "2024-01"


def test_spaces_pull():
    assert default_space_layout.spaces_pull(USER_ID) == f"/pull/user/{USER_ID}/_spaces"


def test_spaces_push():
    assert default_space_layout.spaces_push(USER_ID) == f"/push/user/{USER_ID}/_spaces"


def test_space_access_pull():
    assert default_space_layout.space_access_pull(SPACE_ID) == f"/pull/spaces/{SPACE_ID}/_access"


def test_space_access_push():
    assert default_space_layout.space_access_push(SPACE_ID) == f"/push/spaces/{SPACE_ID}/_access"


def test_keyring_pull():
    path = default_space_layout.keyring_pull(SPACE_ID)
    assert path.startswith("/pull/")
    assert SPACE_ID in path


def test_obj_index_pull():
    path = default_space_layout.obj_index_pull(SPACE_ID)
    assert path.startswith("/pull/")
    assert SPACE_ID in path
    assert "_index" in path


def test_node_keyring_pull():
    path = default_space_layout.node_keyring_pull(SPACE_ID, NODE_ID)
    assert SPACE_ID in path
    assert NODE_ID in path


def test_profile_pull():
    path = default_space_layout.profile_pull(USER_ID)
    assert USER_ID in path


def test_inbox_pull():
    path = default_space_layout.inbox_pull(USER_ID, SHARD)
    assert USER_ID in path
    assert SHARD in path


def test_object_dir_pull():
    path = default_space_layout.object_dir_pull("public")
    assert "public" in path


def test_keyring_name():
    name = default_space_layout.keyring_name(SPACE_ID)
    assert isinstance(name, str)
    assert SPACE_ID in name


def test_node_keyring_name():
    name = default_space_layout.node_keyring_name(SPACE_ID, NODE_ID)
    assert SPACE_ID in name and NODE_ID in name


def test_space_member_scope():
    scope = default_space_layout.space_member_scope(SPACE_ID, True)
    assert "ops" in scope or "collections" in scope or "paths" in scope


def test_node_member_scope():
    scope = default_space_layout.node_member_scope(SPACE_ID, NODE_ID, True)
    assert scope  # non-empty dict


def test_node_member_scope_path_includes_n_segment():
    """Cap-scope paths MUST include /n/ so they match actual storage paths.

    Storage paths: spaces/{spaceId}/objects/n/{nodeId}/_keyring
    Scope path (wrong): spaces/{spaceId}/objects/{nodeId}/**
    Scope path (correct): spaces/{spaceId}/objects/n/{nodeId}/**

    An invited collaborator whose cap was minted with the wrong scope glob gets
    a 403 "request path is outside cap scope" even though the grant is valid.
    Both TS and Python layout MUST use the /n/ segment for cross-language parity.
    """
    scope = default_space_layout.node_member_scope(SPACE_ID, NODE_ID, True)
    path = scope["paths"][0]
    assert f"objects/n/{NODE_ID}" in path, (
        f"node_member_scope path must include /n/ segment: got {path!r}"
    )
    # Read-only variant
    ro_scope = default_space_layout.node_member_scope(SPACE_ID, NODE_ID, False)
    assert "write" not in ro_scope["ops"]
    assert f"objects/n/{NODE_ID}" in ro_scope["paths"][0]


def test_node_stream_scope():
    scope = default_space_layout.node_stream_scope(SPACE_ID, NODE_ID, True)
    assert scope


def test_node_stream_scope_path_includes_n_segment():
    scope = default_space_layout.node_stream_scope(SPACE_ID, NODE_ID, True)
    path = scope["paths"][0]
    assert f"objects/n/{NODE_ID}" in path, (
        f"node_stream_scope path must include /n/ segment: got {path!r}"
    )


def test_node_keyring_scope():
    scope = default_space_layout.node_keyring_scope(SPACE_ID, NODE_ID)
    assert scope


def test_node_keyring_scope_path_includes_n_segment():
    scope = default_space_layout.node_keyring_scope(SPACE_ID, NODE_ID)
    path = scope["paths"][0]
    assert f"objects/n/{NODE_ID}" in path, (
        f"node_keyring_scope path must include /n/ segment: got {path!r}"
    )
    # keyring scope should be read-only
    assert scope["ops"] == ["read", "list"]


def test_owner_scope():
    scope = default_space_layout.owner_scope()
    assert scope


def test_account_scope():
    scope = default_space_layout.account_scope(USER_ID)
    assert scope


@pytest.mark.skipif(not _VECTOR_PATH.exists(), reason="spaces-layout.json not yet generated")
def test_layout_vector():
    data = json.loads(_VECTOR_PATH.read_text())
    space_id = data["spaceId"]
    node_id = data["nodeId"]
    user_id = data["userId"]
    shard = data.get("shard", "2024-01")
    expected = data["paths"]

    assert default_space_layout.spaces_pull(user_id) == expected["spacesPull"]
    assert default_space_layout.spaces_push(user_id) == expected["spacesPush"]
    assert default_space_layout.space_access_pull(space_id) == expected["spaceAccessPull"]
    assert default_space_layout.obj_index_pull(space_id) == expected["objIndexPull"]
    assert default_space_layout.profile_pull(user_id) == expected["profilePull"]
    assert default_space_layout.inbox_pull(user_id, shard) == expected["inboxPull"]
    assert default_space_layout.node_keyring_pull(space_id, node_id) == expected["nodeKeyringPull"]
