"""Space object index — CAS read-modify-write and tree reader.

The object index is a unified plaintext document at
``spaces/{spaceId}/objects/_index`` (version ``v:2``). It lists all nodes in a
space so clients can render the tree without fetching each node individually.

Invite-only nodes have their ``title`` and ``emoji`` stripped before storage so
non-members cannot infer the node's content from the index.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Callable, Optional

from starfish_spaces.cas_retry import run_cas
from starfish_spaces.config import ObjectNode, ObjectsIndex
from starfish_spaces.objects import build_tree, ObjectTreeNode

if TYPE_CHECKING:
    from starfish_sdk import StarfishClient
    from starfish_spaces.session import Session


# ── Serialization helpers ─────────────────────────────────────────────────────


def _serialize_for_index(node: ObjectNode) -> dict[str, Any]:
    """Convert a node to its index representation.

    Invite-only nodes (``access == 'invite'``) have their title and emoji
    stripped so non-members cannot infer content from the public index.
    """
    d = node.to_dict()
    if d.get("access") == "invite":
        d.pop("title", None)
        d.pop("emoji", None)
    return d


def _build_index_payload(
    objects: list[ObjectNode],
    updated_at: Optional[int] = None,
) -> dict[str, Any]:
    return {
        "v": 2,
        "objects": [_serialize_for_index(n) for n in objects],
        "updatedAt": updated_at or int(time.time() * 1000),
    }


# ── Seed / create ─────────────────────────────────────────────────────────────


async def push_index_seed(
    client: "StarfishClient",
    push_path: str,
    base_hash: Optional[str] = None,
) -> None:
    """Push an empty ``v:2`` index document (idempotent first-write)."""
    payload = _build_index_payload([])
    await client.push(push_path, payload, base_hash)


async def seed_space_object_index(
    client: "StarfishClient",
    session: "Session",
    space_id: str,
) -> None:
    """Create the object index for a new space (idempotent)."""
    layout = session.layout
    pull_path = layout.obj_index_pull(space_id)
    push_path = layout.obj_index_push(space_id)

    try:
        result = await client.pull(pull_path)
        base_hash = result.hash if hasattr(result, "hash") else None
        if base_hash:
            return  # already seeded
    except Exception:
        base_hash = None

    await push_index_seed(client, push_path, base_hash)


# ── CAS update ────────────────────────────────────────────────────────────────


async def update_object_index(
    client: "StarfishClient",
    session: "Session",
    space_id: str,
    mutator: Callable[[list[ObjectNode]], Optional[list[ObjectNode]]],
) -> None:
    """CAS read-modify-write the object index for ``space_id``.

    Args:
        client:  The StarfishClient with write access.
        session: The active session.
        space_id: The space to update.
        mutator: A function ``(current_nodes) -> updated_nodes | None``.
            Return ``None`` to abort (no write).  The function MUST be
            idempotent since it may be called multiple times on conflict.
    """
    layout = session.layout
    pull_path = layout.obj_index_pull(space_id)
    push_path = layout.obj_index_push(space_id)

    async def attempt() -> None:
        try:
            result = await client.pull(pull_path)
            data = result.data if hasattr(result, "data") else {}
            base_hash = result.hash if hasattr(result, "hash") else None
        except Exception:
            data = {}
            base_hash = None

        raw_objects = data.get("objects", []) if isinstance(data, dict) else []
        current = [ObjectNode.from_dict(o) for o in raw_objects if isinstance(o, dict)]

        updated = mutator(current)
        if updated is None:
            return  # caller signalled no-op

        payload = _build_index_payload(updated)
        await client.push(push_path, payload, base_hash)

    await run_cas(attempt)


# ── Reader ────────────────────────────────────────────────────────────────────


async def read_object_tree(
    client: "StarfishClient",
    session: "Session",
    space_id: str,
) -> list[ObjectTreeNode]:
    """Pull the object index and return the built tree.

    Returns an empty list on any error (network / missing doc).
    """
    layout = session.layout
    try:
        result = await client.pull(layout.obj_index_pull(space_id))
        data = result.data if hasattr(result, "data") else {}
        raw = data.get("objects", []) if isinstance(data, dict) else []
        nodes = [ObjectNode.from_dict(o) for o in raw if isinstance(o, dict)]
        return build_tree(nodes)
    except Exception:
        return []


__all__ = [
    "push_index_seed",
    "seed_space_object_index",
    "update_object_index",
    "read_object_tree",
]
