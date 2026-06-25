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

Privacy
-------
Never log ``distinct_id``, ``properties``, or ``context``.  Log counts only.
These values ride as opaque strings into Parquet.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from starfish_protocol.constants import PARQUET_MIME_TYPE
from starfish_protocol.plugins import PushHookContext, PushHookResult, ServerPlugin
from starfish_server.router.route_builder import resolve_document_key

from starfish_events.encode import encode_parquet

if TYPE_CHECKING:
    from starfish_server.storage.base import AbstractObjectStore

_log = logging.getLogger(__name__)


def _supports_binary(store: object) -> bool:
    """Return True when *store* has overridden ``put_bytes`` (supports binary writes).

    The base :class:`~starfish_server.storage.base.AbstractObjectStore` raises
    ``NotImplementedError`` on ``put_bytes``.  Any concrete implementation
    (``S3ObjectStore``, ``FilesystemObjectStore``, ``MemoryObjectStore``) overrides
    it and returns ``True`` here.
    """
    from starfish_server.storage.base import AbstractObjectStore as _Base

    return type(store).put_bytes is not _Base.put_bytes


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
        params.  Example: ``"events/{app}/{batchId}"`` →
        ``"events/myapp/<uuid>"``.  The plugin appends ``.parquet`` when the
        resolved key does not already end with it.
    :raises TypeError: When *store* does not override ``put_bytes``.

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

        # Stamp ingest time server-side. Never log event contents.
        dt_now = datetime.now(timezone.utc)
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

        # Resolve the output key from the storagePath template + URL params.
        key = resolve_document_key(storage_path, dict(ctx.params))
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

    return ServerPlugin(name="starfish-events", intercept_push=_intercept_push)


__all__ = ["create_events_server_plugin"]
