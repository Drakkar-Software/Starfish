"""Inbox client helpers.

Implements a monthly-sharded public-write ring buffer for sealed inter-user
messages (invites, resource grants, etc.).  Inbox paths follow the pattern
``/push/inbox/{identity}/{YYYY-MM}`` — each calendar month is a separate shard.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional, TypedDict

if TYPE_CHECKING:
    from starfish_sdk import StarfishClient
    from starfish_spaces.session import Session


class InboxElement(TypedDict):
    """A single element pulled from an inbox shard."""

    ts: int
    data: Any


def inbox_shard(now: Optional[datetime] = None) -> str:
    """Return the current UTC month shard string (``YYYY-MM``)."""
    dt = now or datetime.now(tz=timezone.utc)
    return dt.strftime("%Y-%m")


def inbox_shards(now: Optional[datetime] = None) -> list[str]:
    """Return the current and previous UTC month shard strings (``[current, prev]``)."""
    dt = now or datetime.now(tz=timezone.utc)
    current = dt.strftime("%Y-%m")
    # Previous month
    if dt.month == 1:
        prev = f"{dt.year - 1}-12"
    else:
        prev = f"{dt.year}-{dt.month - 1:02d}"
    return [current, prev]


async def pull_inbox(
    client: "StarfishClient",
    session: "Session",
    identity: str,
    shard: str,
    since: int = 0,
) -> list[InboxElement]:
    """Pull inbox items from ``inbox/{identity}/{shard}`` (best-effort, returns ``[]`` on error).

    Args:
        client:   An authenticated StarfishClient.
        session:  The active session (used for the layout).
        identity: The inbox owner's identity string (usually ``userId``).
        shard:    A month shard string (``YYYY-MM``) or ``"default"``.
        since:    Pull only elements with ``ts > since`` (0 = full pull).

    Returns:
        List of inbox elements (``{ts, data}``), oldest-first, or ``[]`` on error.
    """
    path = session.layout.inbox_pull(identity, shard)
    try:
        items = await client.pull(path, append_field="items", since=since, full=(since == 0))
        if isinstance(items, list):
            return [
                {"ts": el.get("ts", 0), "data": el.get("data")}
                for el in items
                if isinstance(el, dict)
            ]
        return []
    except Exception:
        return []


__all__ = [
    "InboxElement",
    "inbox_shard",
    "inbox_shards",
    "pull_inbox",
]
