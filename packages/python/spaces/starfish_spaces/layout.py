"""Default ``SpaceLayout`` — implements the canonical starfish-spaces path and cap-scope structure.

This is the value used when no ``layout`` override is supplied via
:func:`configure_spaces`.  Any app using the standard Starfish server configuration
can use this directly.

Override individual methods or create a fresh object implementing
:class:`SpaceLayout` to support alternative collection names, deeper namespacing,
or multi-tenant path schemes.
"""

from __future__ import annotations

import hashlib
from typing import Any, Optional

from starfish_spaces.config import SpaceLayout

# ── Constants ─────────────────────────────────────────────────────────────────

OBJECT_COLLECTIONS: list[str] = [
    "spacekeyring",
    "objindex",
    "objlog",
    "objsnap",
    "objdoc",
    "objblob",
    "typeindex",
    "objpub",
    "objpublog",
]
"""Standard object-content collection names.

These are the collections that a space member cap must cover (read / write as
appropriate).  They mirror the server's registered collection list;
changing them requires a matching server-side change.
"""

USER_ID_HEX_LENGTH = 32
"""Length of a userId in hex characters (= first 16 bytes of sha256)."""

RECIPIENT_LABEL_LEN = 8
"""Length of a keyring recipient label in hex characters."""


# ── userId derivation ─────────────────────────────────────────────────────────


async def default_user_id_from_ed_pub(ed_pub_hex: str) -> str:
    """Derive a ``userId`` from an Ed25519 public key.

    Algorithm: ``sha256(edPubBytes)[0:16]`` encoded as lowercase hex (32 chars).
    This is the default ``SpacesConfig.user_id_from_ed_pub`` implementation.
    """
    digest = hashlib.sha256(bytes.fromhex(ed_pub_hex)).digest()
    return digest[:16].hex()


# ── Path prefix helpers ───────────────────────────────────────────────────────


def _pull(rest: str) -> str:
    return f"/pull/{rest}"


def _push(rest: str) -> str:
    return f"/push/{rest}"


# ── Default layout ────────────────────────────────────────────────────────────


class _DefaultSpaceLayout:
    """The canonical starfish-spaces path layout.

    Path conventions:

    - User-personal docs:   ``/pull|push/user/{userId}/<doc>``
    - Space shared docs:    ``/pull|push/spaces/{spaceId}/<doc>``
    - Per-node docs:        ``/pull|push/spaces/{spaceId}/objects/{nodeId}/<doc>``
    - Inbox shards:         ``/pull|push/inbox/{userId}/{YYYY-MM}``
    - Object directory:     ``/pull/_index/objects/<shard>``
    """

    # ── Registry paths ────────────────────────────────────────────────────────

    def spaces_pull(self, user_id: str) -> str:
        return _pull(f"user/{user_id}/_spaces")

    def spaces_push(self, user_id: str) -> str:
        return _push(f"user/{user_id}/_spaces")

    def space_access_pull(self, space_id: str) -> str:
        return _pull(f"spaces/{space_id}/_access")

    def space_access_push(self, space_id: str) -> str:
        return _push(f"spaces/{space_id}/_access")

    # ── Object index paths ────────────────────────────────────────────────────

    def obj_index_pull(self, space_id: str) -> str:
        return _pull(f"spaces/{space_id}/objects/_index")

    def obj_index_push(self, space_id: str) -> str:
        return _push(f"spaces/{space_id}/objects/_index")

    # ── Space-wide keyring paths ──────────────────────────────────────────────

    def keyring_name(self, space_id: str) -> str:
        return f"spaces/{space_id}"

    def keyring_pull(self, space_id: str) -> str:
        return _pull(f"spaces/{space_id}/_keyring")

    def keyring_push(self, space_id: str) -> str:
        return _push(f"spaces/{space_id}/_keyring")

    # ── Per-node keyring paths ────────────────────────────────────────────────

    def node_keyring_name(self, space_id: str, node_id: str) -> str:
        return f"spaces/{space_id}/objects/n/{node_id}"

    def node_keyring_pull(self, space_id: str, node_id: str) -> str:
        return _pull(f"spaces/{space_id}/objects/n/{node_id}/_keyring")

    def node_keyring_push(self, space_id: str, node_id: str) -> str:
        return _push(f"spaces/{space_id}/objects/n/{node_id}/_keyring")

    # ── Inbox paths ───────────────────────────────────────────────────────────

    def inbox_pull(self, identity: str, shard: Optional[str] = None) -> str:
        if shard:
            return _pull(f"inbox/{identity}/{shard}")
        return _pull(f"inbox/{identity}/default")

    def inbox_push(self, identity: str, shard: Optional[str] = None) -> str:
        if shard:
            return _push(f"inbox/{identity}/{shard}")
        return _push(f"inbox/{identity}/default")

    # ── Profile paths ─────────────────────────────────────────────────────────

    def profile_pull(self, user_id: str) -> str:
        return _pull(f"user/{user_id}/profile")

    def profile_push(self, user_id: str) -> str:
        return _push(f"user/{user_id}/profile")

    # ── Object directory ──────────────────────────────────────────────────────

    def object_dir_pull(self, shard: Optional[str] = None) -> str:
        return _pull(f"_index/objects/{shard or 'public'}")

    # ── Cap scopes ────────────────────────────────────────────────────────────

    def owner_scope(self) -> dict[str, Any]:
        return {
            "ops": ["read", "write", "list"],
            "collections": ["*"],
            "paths": ["**"],
        }

    def space_owner_scope(self, space_id: str) -> dict[str, Any]:
        return {
            "ops": ["read", "write", "list"],
            "collections": OBJECT_COLLECTIONS,
            "paths": [f"spaces/{space_id}/**"],
        }

    def space_member_scope(self, space_id: str, can_write: bool) -> dict[str, Any]:
        return {
            "ops": ["read", "write", "list"] if can_write else ["read", "list"],
            "collections": OBJECT_COLLECTIONS,
            "paths": [f"spaces/{space_id}/**"],
        }

    def node_member_scope(self, space_id: str, node_id: str, can_write: bool) -> dict[str, Any]:
        # Cap-scope paths MUST include the /n/ segment so they match the actual
        # storage paths (e.g. objects/n/{nodeId}/_keyring, objects/n/{nodeId}/log).
        # TS layout uses `objects/n/${nodeId}/**` for the same reason — omitting /n/
        # causes `matchScopePath` to fail with "request path is outside cap scope" even
        # for legitimately-invited collaborators.
        return {
            "ops": ["read", "write", "list"] if can_write else ["read", "list"],
            "collections": ["objinv"],
            "paths": [f"spaces/{space_id}/objects/n/{node_id}/**"],
        }

    def node_stream_scope(self, space_id: str, node_id: str, can_write: bool) -> dict[str, Any]:
        return {
            "ops": ["read", "write", "list"] if can_write else ["read", "list"],
            "collections": ["objinvlog"],
            "paths": [f"spaces/{space_id}/objects/n/{node_id}/**"],
        }

    def node_keyring_scope(self, space_id: str, node_id: str) -> dict[str, Any]:
        return {
            "ops": ["read", "list"],
            "collections": ["nodekeyring"],
            "paths": [f"spaces/{space_id}/objects/n/{node_id}/**"],
        }

    def account_scope(self, user_id: str) -> dict[str, Any]:
        return {
            "ops": ["read", "write", "list"],
            "collections": ["*"],
            "paths": [f"user/{user_id}/**", "spaces/**", f"inbox/{user_id}/**"],
        }

    def linked_device_scope(self, user_id: str) -> dict[str, Any]:
        return {
            "ops": ["read", "write", "list"],
            "collections": ["*"],
            "paths": [f"user/{user_id}/**", "spaces/**", f"inbox/{user_id}/**"],
        }


default_space_layout: SpaceLayout = _DefaultSpaceLayout()  # type: ignore[assignment]
"""The canonical starfish-spaces :class:`SpaceLayout` — ready-to-use default."""


__all__ = [
    "OBJECT_COLLECTIONS",
    "USER_ID_HEX_LENGTH",
    "RECIPIENT_LABEL_LEN",
    "default_user_id_from_ed_pub",
    "default_space_layout",
]
