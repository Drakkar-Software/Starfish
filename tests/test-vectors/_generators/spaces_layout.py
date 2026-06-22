"""Generate tests/test-vectors/spaces-layout.json.

Generates deterministic paths and scope dicts from ``default_space_layout``
for a fixed (spaceId, nodeId, userId, shard) tuple.  Both TS and Python load
the same JSON file and assert identical output.

Usage::

    uv run --python 3.12 python tests/test-vectors/_generators/spaces_layout.py

from the repo root, or::

    python spaces_layout.py

from inside _generators/ after adding the repo root to sys.path.
"""

from __future__ import annotations

import json
import pathlib
import sys

# Make the repo root importable when run directly from the _generators dir.
_REPO_ROOT = pathlib.Path(__file__).parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Add spaces package to path.
_SPACES_PKG = _REPO_ROOT / "packages" / "python" / "spaces"
if str(_SPACES_PKG) not in sys.path:
    sys.path.insert(0, str(_SPACES_PKG))

from starfish_spaces.layout import default_space_layout  # noqa: E402

SPACE_ID = "sp-0000000000000001"
NODE_ID = "obj-0000000000000001"
USER_ID = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"  # 32 hex chars
SHARD = "2024-01"

paths = {
    "spacesPull": default_space_layout.spaces_pull(USER_ID),
    "spacesPush": default_space_layout.spaces_push(USER_ID),
    "spaceAccessPull": default_space_layout.space_access_pull(SPACE_ID),
    "spaceAccessPush": default_space_layout.space_access_push(SPACE_ID),
    "keyringPull": default_space_layout.keyring_pull(SPACE_ID),
    "keyringPush": default_space_layout.keyring_push(SPACE_ID),
    "objIndexPull": default_space_layout.obj_index_pull(SPACE_ID),
    "objIndexPush": default_space_layout.obj_index_push(SPACE_ID),
    "profilePull": default_space_layout.profile_pull(USER_ID),
    "profilePush": default_space_layout.profile_push(USER_ID),
    "inboxPull": default_space_layout.inbox_pull(USER_ID, SHARD),
    "inboxPush": default_space_layout.inbox_push(USER_ID, SHARD),
    "nodeKeyringPull": default_space_layout.node_keyring_pull(SPACE_ID, NODE_ID),
    "nodeKeyringPush": default_space_layout.node_keyring_push(SPACE_ID, NODE_ID),
    "objectDirPull": default_space_layout.object_dir_pull("public"),
}

scopes = {
    "spaceMemberScopeWrite": default_space_layout.space_member_scope(SPACE_ID, True),
    "spaceMemberScopeRead": default_space_layout.space_member_scope(SPACE_ID, False),
    "nodeMemberScopeWrite": default_space_layout.node_member_scope(SPACE_ID, NODE_ID, True),
    "nodeStreamScopeWrite": default_space_layout.node_stream_scope(SPACE_ID, NODE_ID, True),
    "nodeKeyringScope": default_space_layout.node_keyring_scope(SPACE_ID, NODE_ID),
    "ownerScope": default_space_layout.owner_scope(),
    "accountScope": default_space_layout.account_scope(USER_ID),
}

out = {
    "spaceId": SPACE_ID,
    "nodeId": NODE_ID,
    "userId": USER_ID,
    "shard": SHARD,
    "paths": paths,
    "scopes": scopes,
}

OUTPUT = _REPO_ROOT / "tests" / "test-vectors" / "spaces-layout.json"
OUTPUT.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
print(f"wrote {OUTPUT}")
