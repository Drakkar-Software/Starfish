"""Starfish server plugin: intercepts JSON event-batch pushes and encodes them
as Parquet files written directly to the object store (typically S3).

How it works
------------
1. Register a JSON-typed collection (``allowed_mime_types: ["application/json"]``)
   with public write access.
2. Attach this plugin to the sync router.
3. Each push to that collection is intercepted here; the JSON event batch is
   encoded as Parquet and stored via ``store.put_bytes``, short-circuiting the
   default JSON document write so no JSON is persisted alongside the Parquet.

Collection requirement
-----------------------
The intercepted collection **must** be JSON-typed — ``intercept_push`` only
receives a populated ``raw_body`` for JSON collections (see
``route_builder.py:847``).  A binary (Parquet-typed) collection would yield an
empty body.

One file per batch
------------------
Parquet's column-footer format makes in-place append impractical.  Each
``send()`` call from the SunGlasses adapter writes a unique path (batchId in
the storage-path template). DuckDB's
``read_parquet('s3://…/**/*.parquet')`` glob treats all files under the prefix
as one logical dataset.

Batch id
--------
The plugin — not the client — assigns the final ``{batchId}`` path segment: a
server-clock-derived, lexicographically-sortable id (see ``sortable_id.py``).
The client's URL still carries a ``{batchId}`` placeholder value, but it's
discarded. This makes the ``/list`` route's ascending key order double as a
chronological cursor, which a client-minted id can't guarantee — batches come
from many end-user devices with untrusted, possibly-skewed clocks.

Privacy
-------
Never log ``distinct_id``, ``properties``, or ``context``.  Log counts only.
These values ride as opaque strings into Parquet.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from starfish_protocol.constants import PARQUET_MIME_TYPE
from starfish_protocol.plugins import (
    InterceptPullResult,
    PullHookContext,
    PushHookContext,
    PushHookResult,
    ServerPlugin,
)
from starfish_server.router.route_builder import resolve_document_key

from starfish_events.encode import encode_parquet
from starfish_events.sortable_id import generate_sortable_batch_id

if TYPE_CHECKING:
    from starfish_server.storage.base import AbstractObjectStore

_log = logging.getLogger(__name__)

_LAST_PATH_PARAM_RE = re.compile(r"^\{([^}]+)\}$")


def _supports_binary(store: object) -> bool:
    """Return True when *store* has overridden ``put_bytes`` (supports binary writes).

    The base :class:`~starfish_server.storage.base.AbstractObjectStore` raises
    ``NotImplementedError`` on ``put_bytes``.  Any concrete implementation
    (``S3ObjectStore``, ``FilesystemObjectStore``, ``MemoryObjectStore``) overrides
    it and returns ``True`` here.
    """
    from starfish_server.storage.base import AbstractObjectStore as _Base

    return type(store).put_bytes is not _Base.put_bytes


def _last_path_param_name(storage_path: str) -> str:
    """Extract the ``{param}`` name from the last ``storage_path`` segment
    (e.g. ``"batchId"`` from ``"{batchId}"``)."""
    last_segment = storage_path.rstrip("/").split("/")[-1]
    match = _LAST_PATH_PARAM_RE.match(last_segment)
    if not match:
        raise ValueError(
            f'[starfish-events] storage_path "{storage_path}" must end with a '
            '{param} segment (e.g. "events/{app}/{batchId}")'
        )
    return match.group(1)


def create_events_server_plugin(
    *,
    store: "AbstractObjectStore",
    collection: str,
    storage_path: str,
) -> ServerPlugin:
    """Build a :class:`~starfish_protocol.plugins.ServerPlugin` that encodes
    SunGlasses event batches as Parquet and writes them to the object store.

    :param store: Object store the plugin writes Parquet files to.  Must
        implement ``put_bytes`` (e.g. ``S3ObjectStore`` or ``MemoryObjectStore``).
        Pass the **same** store instance you pass to ``create_sync_router``.
    :param collection: Name of the collection to intercept.  Must match the
        ``name`` field in the ``SyncConfig.collections`` entry.
        Example: ``"events"``.
    :param storage_path: Storage-path template for the output Parquet key.
        Supports ``{param}`` placeholders resolved from the push URL's path
        params, except the **last** segment, which must be a ``{param}`` too
        but is always overridden with a server-assigned sortable batch id
        (see "Batch id" above) rather than the client-supplied value.
        Example: ``"events/{app}/{batchId}"`` →
        ``"events/myapp/<server-assigned-id>"``.  The plugin appends
        ``.parquet`` when the resolved key does not already end with it.
    :raises TypeError: When *store* does not override ``put_bytes``.
    :raises ValueError: When *storage_path* doesn't end with a ``{param}``
        segment.

    Example wiring::

        from starfish_server.storage.s3 import S3ObjectStore
        from starfish_events import create_events_server_plugin

        store = S3ObjectStore(...)
        plugin = create_events_server_plugin(
            store=store,
            collection="events",
            storage_path="events/{app}/{batchId}",
        )
        router = create_sync_router(
            SyncRouterOptions(
                store=store,
                config=SyncConfig(
                    version=1,
                    collections=[
                        CollectionConfig(
                            name="events",
                            storage_path="events/{app}/{batchId}",
                            read_roles=["admin"],
                            write_roles=["public"],
                            encryption="none",
                            allowed_mime_types=["application/json"],  # JSON-typed!
                            max_body_bytes=8_000_000,
                        )
                    ],
                ),
                plugins=[plugin],
            )
        )
    """
    if not _supports_binary(store):
        raise TypeError(
            "[starfish-events] the provided store does not implement put_bytes "
            "(binary writes). Use S3ObjectStore, FilesystemObjectStore, or "
            "MemoryObjectStore."
        )

    # The last storage_path segment names the batch-id param (e.g. "{batchId}"
    # in "events/{app}/{batchId}"). Resolved once at construction so a
    # misconfigured template fails fast at startup rather than on first push.
    batch_id_param = _last_path_param_name(storage_path)

    async def _intercept_push(ctx: PushHookContext) -> PushHookResult:
        # Only intercept the configured collection; let everything else proceed.
        if ctx.collection != collection:
            return PushHookResult(action="proceed")

        # Parse the push envelope: { data: { events: [...] }, baseHash }
        try:
            envelope = json.loads(ctx.raw_body)
            data = (envelope.get("data") or {}) if isinstance(envelope, dict) else {}
            raw = data.get("events") if isinstance(data, dict) else None
            events: list[dict] = raw if isinstance(raw, list) else []
        except (json.JSONDecodeError, AttributeError, ValueError):
            return PushHookResult(
                action="reject",
                status=400,
                error="Invalid JSON body — expected { data: { events: [...] }, baseHash }",
            )

        # Stamp ingest time server-side. Never log event contents. The batch id
        # below is minted from this same instant, so the filename and
        # received_at agree.
        now_ms = time.time_ns() // 1_000_000
        dt_now = datetime.fromtimestamp(now_ms / 1000, tz=timezone.utc)
        received_at = (
            dt_now.strftime("%Y-%m-%dT%H:%M:%S.")
            + f"{dt_now.microsecond // 1000:03d}Z"
        )
        rows = [{**e, "received_at": received_at} for e in events]

        # Encode to Parquet.
        try:
            parquet_bytes = encode_parquet(rows)
        except Exception as exc:
            _log.error("[starfish-events] Parquet encoding failed: %s", exc)
            return PushHookResult(action="reject", status=500, error="Parquet encoding failed")

        # Resolve the output key from the storage_path template + URL params,
        # but override the batch-id param with a server-assigned,
        # lexicographically-sortable id — never the client-supplied one.
        # Batches arrive from many end-user devices with untrusted clocks, so
        # only a single server clock can make the /list route's ascending key
        # order a correct chronological cursor.
        server_batch_id = generate_sortable_batch_id(now_ms)
        params = {**dict(ctx.params), batch_id_param: server_batch_id}
        key = resolve_document_key(storage_path, params)
        if not key.endswith(".parquet"):
            key += ".parquet"

        # Write to the object store. On failure return a clean HTTP 500 so the
        # SunGlasses adapter sees a non-2xx and the SDK requeues the batch
        # (at-least-once delivery guarantee).
        try:
            await store.put_bytes(key, parquet_bytes, content_type=PARQUET_MIME_TYPE)
        except Exception as exc:
            _log.error("[starfish-events] put_bytes failed for key %r: %s", key, exc)
            return PushHookResult(action="reject", status=500, error="Storage write failed")

        # Compute SHA-256 to match the binary push response format.
        sha = hashlib.sha256(parquet_bytes).hexdigest()

        # Privacy: log only counts, never event contents.
        _log.info(
            "[starfish-events] wrote %d event(s) → %s (%d bytes)",
            len(events),
            key,
            len(parquet_bytes),
        )

        return PushHookResult(action="respond", status=200, body={"hash": sha})

    async def _intercept_pull(ctx: PullHookContext) -> InterceptPullResult:
        # Only handle the configured collection.
        if ctx.collection != collection:
            return InterceptPullResult(action="proceed")

        # Resolve the same key the push hook wrote (storage_path + params + .parquet).
        key = resolve_document_key(storage_path, dict(ctx.params))
        if not key.endswith(".parquet"):
            key += ".parquet"

        result = await store.get_bytes(key)
        if result is None:
            return InterceptPullResult(action="proceed")

        raw_bytes, content_type = result
        return InterceptPullResult(
            action="respond",
            status=200,
            body=raw_bytes,
            content_type=content_type,
        )

    return ServerPlugin(
        name="starfish-events",
        intercept_push=_intercept_push,
        intercept_pull=_intercept_pull,
    )


__all__ = ["create_events_server_plugin"]
