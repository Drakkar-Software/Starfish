# starfish-events

Starfish server plugin that intercepts JSON event-batch pushes and encodes them as
[Apache Parquet](https://parquet.apache.org/) files written to any configured object
store — S3, filesystem, memory, or custom. The plugin has no direct S3 dependency;
it writes through the abstract `AbstractObjectStore.put_bytes` interface. The DuckDB
query examples below use S3; see [Storage backends](/analytics/events#storage-backends)
for non-S3 alternatives.

Mirrors [`@drakkar.software/starfish-events`](../ts/events) (TypeScript) with
identical Parquet encoding — both are locked to the same test vectors.

## Install

```bash
pip install starfish-events
```

## How it works

1. Register a JSON-typed collection (`allowed_mime_types: ["application/json"]`) in
   your `SyncConfig`.
2. Attach `create_events_server_plugin` to `create_sync_router`.
3. Each push to that collection is intercepted: the JSON event batch is encoded as
   Parquet and written via `store.put_bytes`, at a **server-assigned batch id**
   (see [Batch id](#batch-id) below) — not the client's. The default JSON document
   write is short-circuited — **no JSON is persisted alongside the Parquet**.

One Parquet file is written per push (one file per batch). For S3-backed stores,
DuckDB's `read_parquet('s3://…/**/*.parquet')` glob treats all files under the prefix
as one logical dataset.

## Usage

```python
from starfish_server.storage.s3 import S3ObjectStore
from starfish_server.router.sync_router import create_sync_router
from starfish_protocol.config import SyncConfig, CollectionConfig, SyncRouterOptions
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
                    allowed_mime_types=["application/json"],  # JSON-typed, not Parquet
                    max_body_bytes=8_000_000,
                )
            ],
        ),
        plugins=[plugin],
    )
)
```

## Batch id

The plugin — not the client — assigns the final `{batchId}` path segment: a
server-clock-derived, lexicographically-sortable id (13-digit epoch-ms + a
per-ms counter + a random suffix, e.g. `1782933157690-0000-735223`). The
client's push URL still carries a `{batchId}` placeholder value, but it's
discarded.

This matters for **listing**: if the collection is also `listable=True`,
`GET /list/<collection>/<app>` returns stored batch ids in ascending
lexicographic order, which — because the id is server-clock-derived — is also
chronological order. A caller can persist the last-seen id and pass it back as
`?after=<id>` to fetch only batches written since then, instead of re-listing
from the beginning every time. A client-minted id couldn't give that
guarantee: batches are pushed from many end-user devices with untrusted,
possibly-skewed clocks, so a lexicographic cursor over client timestamps could
permanently miss a batch from a clock-skewed-slow device.

Ordering is guaranteed only *within one server process* — multiple sync-server
instances each mint their own monotonic sequence.

## Pull

A `GET /pull/<collection>/<params>` request also returns the stored Parquet file
for the matching key. The server responds with `Content-Type: application/vnd.apache.parquet`
and a strong `ETag` header. Conditional GETs (`If-None-Match`) return `304 Not Modified`
when the bytes haven't changed.

If no batch was pushed for that key yet, the response falls through to the normal
sync-protocol JSON response (200 with empty data).

## API

### `create_events_server_plugin(*, store, collection, storage_path) -> ServerPlugin`

| Parameter | Type | Description |
|---|---|---|
| `store` | `AbstractObjectStore` | Object store with `put_bytes` / `get_bytes`. Pass the same instance as `create_sync_router`. |
| `collection` | `str` | Name of the collection to intercept (e.g. `"events"`). |
| `storage_path` | `str` | Storage-path template for the Parquet key. Supports `{param}` placeholders from the push/pull URL, except the **last** segment (also required to be a `{param}`), which is always overridden with a server-assigned sortable batch id — see [Batch id](#batch-id). The `.parquet` extension is appended automatically if absent. |

The plugin adds `received_at` (ISO-8601 UTC) to every event row before encoding.

## Querying with DuckDB

**S3-backed stores** — requires the `httpfs` extension and S3 credentials:

```sql
SELECT event_type, COUNT(*) AS n
FROM read_parquet('s3://my-bucket/events/myapp/**/*.parquet')
GROUP BY event_type
ORDER BY n DESC;
```

**Filesystem-backed stores** — no `httpfs` or credentials needed:

```sql
SELECT event_type, COUNT(*) AS n
FROM read_parquet('/data/root/events/myapp/**/*.parquet')
GROUP BY event_type
ORDER BY n DESC;
```

See [Analytics — Events & Parquet](/analytics/events) for the full guide, including
the [storage backend matrix](/analytics/events#storage-backends).
