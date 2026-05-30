"""Server plugin for the projection (incremental-list) extension (Python mirror).

Implements the ``after_write`` write-path hook from the ``ServerPlugin``
contract: after a successful push the server hands the plugin a
:class:`WriteEvent`; for any projection whose ``source`` includes the event's
collection, the plugin runs the app-supplied pure ``project(event)`` mapping and
folds its outcome into a single target *list document* — appending a new entry,
replacing an existing one in place (:class:`ProjectionSet`), or removing it
(:class:`ProjectionRemove`); ``None`` ignores the event. The app supplies only
the mapping; the plugin owns all store IO. The client then pulls one document to
read the whole list, rather than enumerating a directory of per-entry documents.

The list is written in-process, directly against the object store — never over
HTTP — so the target collection can be configured ``pull_only=True`` to reject
every *client* write while still being populated here. That ``pull_only`` + this
plugin is how a target list becomes "owned by the indexer": clients read it, but
only the projection writes it.

Concurrency: many source writes can target the same list at once, so each apply
is a CAS loop — pull the current list, fold the entry in, then ``push`` with the
pulled ``base_hash``. ``push`` rejects on a stale hash (optimistic concurrency),
so on conflict we re-pull and re-apply onto fresh state rather than clobbering a
concurrent write. The pull MUST happen inside the loop so each retry sees the
latest list. Failures are logged, never raised — ``after_write`` must not break
the originating client write (same contract as starfish-queuing).

Scale: every write rewrites and re-hashes the whole list document under one
per-key lock, and in-process pushes bypass the HTTP ``max_body_bytes`` limit, so
a single list can grow unbounded server-side. Keep lists bounded — shard via a
``target`` function (one list per tenant/bucket) and/or set ``max_items``.
"""

from __future__ import annotations

import inspect
import logging
from typing import Sequence

from starfish_protocol.plugins import ServerPlugin, WriteEvent
from starfish_server.protocol.pull import pull
from starfish_server.protocol.push import push
from starfish_server.protocol.types import PushConflict
from starfish_server.storage.base import AbstractObjectStore, StoreContext

from starfish_projection.config import Projection, ProjectionOp, ProjectionRemove

_log = logging.getLogger(__name__)

DEFAULT_MAX_RETRIES = 8


def _source_set(source: str | Sequence[str]) -> frozenset[str]:
    return frozenset([source] if isinstance(source, str) else source)


async def _apply_op(
    store: AbstractObjectStore,
    target_key: str,
    op: ProjectionOp,
    max_retries: int,
    max_items: int | None,
    source_collection: str,
) -> None:
    """Fold a single entry op into the target list document under a CAS retry loop."""
    # A projection-owned write runs in-process with the plugin's authority, not a
    # client's — no per-document role gating.
    ctx = StoreContext(
        collection=source_collection,
        params={},
        identity=None,
        roles=(),
        action="push",
    )

    for _ in range(max_retries):
        # Re-pull every iteration so each retry folds onto the latest list.
        current = await pull(store, target_key, context=ctx)
        base_hash = current.hash or None
        stored = current.data.get("items") if isinstance(current.data, dict) else None
        items = list(stored) if isinstance(stored, list) else []
        idx = next((i for i, it in enumerate(items) if it.get("id") == op.id), -1)

        if isinstance(op, ProjectionRemove):
            if idx == -1:
                return  # already absent — nothing to write
            items.pop(idx)
        elif idx == -1:
            if max_items is not None and len(items) >= max_items:
                _log.warning(
                    "projection list %r at max_items=%d; dropping append of id %r",
                    target_key,
                    max_items,
                    op.id,
                )
                return
            items.append({"id": op.id, "value": op.value})
        else:
            # Update in place: keep the entry's position, full-replace its value.
            items[idx] = {"id": op.id, "value": op.value}

        result = await push(store, target_key, {"items": items}, base_hash, context=ctx)
        if not isinstance(result, PushConflict):
            return  # PushSuccess — done
        # hash_mismatch: a concurrent write changed the list; loop to re-pull/re-apply.

    _log.warning(
        "projection list %r exhausted %d CAS retries; dropped op for id %r",
        target_key,
        max_retries,
        op.id,
    )


def create_projection_server_plugin(
    *,
    store: AbstractObjectStore,
    projections: list[Projection],
    max_retries: int = DEFAULT_MAX_RETRIES,
    max_items: int | None = None,
) -> ServerPlugin:
    """Build a :class:`ServerPlugin` that maintains one or more projection lists:
    after a successful push to a watched ``source`` collection, it derives an
    entry op via the app's ``project`` function and folds it into the target list
    document in *store*.

    ``max_retries`` (default 8) bounds the CAS loop; on exhaustion the op is
    logged and dropped. ``max_items`` optionally caps each list — once full,
    further appends are logged and dropped (existing entries are never evicted);
    prefer sharding via a ``target`` function for large views.
    """

    compiled = [(_source_set(p.source), p.target, p.project) for p in projections]

    async def _after_write(event: WriteEvent) -> None:
        for sources, target, project in compiled:
            if event.collection not in sources:
                continue
            try:
                # Resolve the target list before running the mapping; None = ignore.
                target_key = target(event) if callable(target) else target
                if target_key is None:
                    continue
                op = project(event)
                if inspect.isawaitable(op):
                    op = await op
                if op is None:
                    continue
                await _apply_op(
                    store, target_key, op, max_retries, max_items, event.collection
                )
            except Exception as exc:  # noqa: BLE001 — must not break client writes
                _log.warning("projection for %r failed: %s", event.collection, exc)

    return ServerPlugin(name="starfish-projection", after_write=_after_write)


__all__ = ["create_projection_server_plugin"]
