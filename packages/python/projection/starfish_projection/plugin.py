"""Server plugin for the projection (materialized-view) extension (Python mirror).

Implements the ``after_write`` write-path hook from the ``ServerPlugin``
contract: after a successful push the server hands the plugin a
:class:`WriteEvent`; for any projection whose ``source`` includes the event's
collection, the plugin runs the app-supplied pure ``project(event)`` mapping and
applies its outcome to the ``store`` — UPSERT (:class:`ProjectionUpsert`), DELETE
(:class:`ProjectionDelete`), or IGNORE (``None``). The app supplies only the
mapping; the plugin owns all store IO.

The view is written in-process, directly against the object store — never over
HTTP — so the target collection can be configured ``pull_only=True`` to reject
every *client* write while still being populated here. That ``pull_only`` + this
plugin is how a target view becomes "owned by the indexer": clients can read and
(if ``listable``) enumerate it, but only the projection writes it.

Writes use the server's ``push`` helper, so the stored document is byte-identical
to a normal pushed document and the pull / list-with-values / batch-pull paths
read it back unchanged. Each upsert reads the current hash first and passes it as
``base_hash``, so a projection overwrites the previous view value
(last-writer-wins by key). Failures are logged, never raised — ``after_write``
must not break the originating client write (same contract as starfish-queuing).
"""

from __future__ import annotations

import inspect
import logging
from typing import Sequence

from starfish_protocol.plugins import ServerPlugin, WriteEvent
from starfish_server.protocol.pull import pull
from starfish_server.protocol.push import push
from starfish_server.storage.base import AbstractObjectStore, StoreContext

from starfish_projection.config import Projection, ProjectionDelete, ProjectionUpsert

_log = logging.getLogger(__name__)


def _source_set(source: str | Sequence[str]) -> frozenset[str]:
    return frozenset([source] if isinstance(source, str) else source)


def create_projection_server_plugin(
    *,
    store: AbstractObjectStore,
    projections: list[Projection],
) -> ServerPlugin:
    """Build a :class:`ServerPlugin` that maintains one or more materialized
    views: after a successful push to a watched ``source`` collection, it derives
    a target document via the app's ``project`` function and upserts/deletes it in
    *store*."""

    compiled = [(_source_set(p.source), p.project) for p in projections]

    async def _after_write(event: WriteEvent) -> None:
        for sources, project in compiled:
            if event.collection not in sources:
                continue
            try:
                result = project(event)
                if inspect.isawaitable(result):
                    result = await result
                if result is None:
                    continue

                if isinstance(result, ProjectionDelete):
                    ctx = StoreContext(
                        collection=event.collection,
                        params={},
                        identity=None,
                        roles=(),
                        action="delete",
                    )
                    await store.delete(result.key, context=ctx)
                    continue

                if isinstance(result, ProjectionUpsert):
                    ctx = StoreContext(
                        collection=event.collection,
                        params={},
                        identity=None,
                        roles=(),
                        action="push",
                    )
                    # Read the current hash so the upsert overwrites cleanly (the
                    # view is last-writer-wins by key, not concurrency controlled).
                    current = await pull(store, result.key, context=ctx)
                    base_hash = current.hash or None
                    await push(store, result.key, result.data, base_hash, context=ctx)
            except Exception as exc:  # noqa: BLE001 — must not break client writes
                _log.warning(
                    "projection for %r failed: %s", event.collection, exc
                )

    return ServerPlugin(name="starfish-projection", after_write=_after_write)


__all__ = ["create_projection_server_plugin"]
