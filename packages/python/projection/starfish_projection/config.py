"""Projection (materialized-view) configuration types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable, Sequence

from starfish_protocol.plugins import WriteEvent


@dataclass
class ProjectionUpsert:
    """UPSERT outcome: write ``data`` as the target document at storage ``key``."""

    key: str
    data: dict


@dataclass
class ProjectionDelete:
    """DELETE outcome: remove the target document at storage ``key``."""

    key: str


# A projection function returns an upsert, a delete, or ``None`` (ignore).
ProjectionResult = ProjectionUpsert | ProjectionDelete | None

ProjectFn = Callable[[WriteEvent], "ProjectionResult | Awaitable[ProjectionResult]"]


@dataclass
class Projection:
    """A single materialized view.

    On every write to one of ``source`` collections, ``project`` derives a target
    document (:class:`ProjectionUpsert`), a deletion (:class:`ProjectionDelete`),
    or nothing (``None``). The plugin owns the read-modify-write against the store
    — the app only supplies the pure mapping.

    ``project`` MUST be a pure function of the event: it receives the
    :class:`WriteEvent` (carrying ``collection``, ``params``, optional ``body``,
    ``hash``, ``timestamp``, ``identity``) and returns a ``ProjectionResult``. To
    see the pushed document body, the server populates ``WriteEvent.body`` for
    JSON pushes; ``params`` is always present.
    """

    source: str | Sequence[str]
    project: ProjectFn
