"""Projection (incremental-list) configuration types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable, Sequence

from starfish_protocol.plugins import WriteEvent


@dataclass
class ProjectionSet:
    """UPSERT outcome: append the entry ``{id, value}`` to the target list, or —
    if an entry with this ``id`` already exists — replace its ``value`` in place
    (keeping its position)."""

    id: str
    value: dict


@dataclass
class ProjectionRemove:
    """REMOVE outcome: drop the entry with this ``id`` from the target list (a
    no-op if absent). The server has no delete route, so a removal is signalled by
    a normal write whose body your mapping recognises as a deletion (a
    tombstone)."""

    id: str


# A projection function returns an upsert, a remove, or ``None`` (ignore).
ProjectionOp = ProjectionSet | ProjectionRemove | None

ProjectFn = Callable[[WriteEvent], "ProjectionOp | Awaitable[ProjectionOp]"]

# Where a projection writes its list: a fixed storage key, or a function of the
# event returning a key (route the entry into that list) or ``None`` (ignore).
ProjectionTarget = str | Callable[[WriteEvent], "str | None"]


@dataclass
class Projection:
    """A single projection list.

    On every write to one of ``source`` collections, ``project`` derives an entry
    op which the plugin folds into the target list document
    (:class:`ProjectionSet` → append / update-in-place, :class:`ProjectionRemove`
    → remove, ``None`` → ignore). The plugin owns the read-modify-write against
    the store — the app only supplies the pure mapping.

    ``project`` MUST be a pure function of the event: it receives the
    :class:`WriteEvent` (carrying ``collection``, ``params``, optional ``body``,
    ``hash``, ``timestamp``, ``identity``). The server populates
    ``WriteEvent.body`` for JSON pushes; ``params`` is always present.

    ``target`` is a fixed storage key or a function of the event; return ``None``
    from the function to ignore the event, or a per-bucket key to shard a large
    view into many small lists (e.g. one per tenant).
    """

    source: str | Sequence[str]
    target: ProjectionTarget
    project: ProjectFn
