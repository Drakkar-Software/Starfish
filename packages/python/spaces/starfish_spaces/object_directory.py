"""Client-side reader for the global public-object directory.

The directory is a server-maintained projection doc at
``_index/objects/{shard}`` (collection ``objectindex``, ``readRoles:["public"]``,
``pullOnly``). It is populated by the ``starfish-spaces`` server plugin from
``objindex`` writes. Any node with ``access:'public'`` across any space appears here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from starfish_spaces.session import Session


# ── Types ─────────────────────────────────────────────────────────────────────


@dataclass
class ObjectDirectoryEntry:
    """A single public object entry in the global directory."""

    space_id: str
    id: str
    title: str
    type: str
    updated_at: int
    emoji: Optional[str] = None


# ── Pure parser ───────────────────────────────────────────────────────────────


def parse_object_directory_doc(data: Any) -> list[ObjectDirectoryEntry]:
    """Convert the raw directory doc body to a flat ``ObjectDirectoryEntry`` list.

    Pure function — directly unit-testable without network mocks.

    Args:
        data: The raw ``data`` field from a ``client.pull()`` result.

    Returns:
        A flat list of entries (public nodes across all spaces), or ``[]`` on
        malformed / missing input.
    """
    if not isinstance(data, dict):
        return []
    entries: list[ObjectDirectoryEntry] = []
    for space_id, bucket in data.items():
        if not isinstance(bucket, dict):
            continue
        nodes = bucket.get("nodes")
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            if not isinstance(node, dict):
                continue
            entry = ObjectDirectoryEntry(
                space_id=space_id,
                id=str(node.get("id", "")),
                title=str(node.get("title", "")) if isinstance(node.get("title"), str) else "",
                type=str(node.get("type", "page")) if isinstance(node.get("type"), str) else "page",
                updated_at=int(node.get("updatedAt", 0)) if isinstance(node.get("updatedAt"), (int, float)) else 0,
                emoji=str(node.get("emoji")) if isinstance(node.get("emoji"), str) else None,
            )
            entries.append(entry)
    return entries


# ── Network reader ────────────────────────────────────────────────────────────


async def read_object_directory(
    session: "Session",
    shard: str = "public",
) -> list[ObjectDirectoryEntry]:
    """Pull the global public-object directory and return a flat entry list.

    No authentication required — the directory collection is world-readable.
    Returns an empty list on network error or empty/malformed directory.

    Args:
        session: The current session (provides ``baseUrl``, ``namespace``, and layout).
        shard:   Directory shard key (default ``'public'``).
    """
    from starfish_spaces.client import make_anon_space_client, ClientOpts

    anon_opts: ClientOpts = {"baseUrl": session.base_url, "namespace": session.namespace}  # type: ignore[misc]
    client = make_anon_space_client(anon_opts)
    try:
        result = await client.pull(session.layout.object_dir_pull(shard))
        data = result.data if hasattr(result, "data") else result
    except Exception:
        return []
    return parse_object_directory_doc(data)


__all__ = [
    "ObjectDirectoryEntry",
    "parse_object_directory_doc",
    "read_object_directory",
]
