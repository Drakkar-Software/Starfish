---
sidebar_position: 2
---

# Events Plugin — JSON push → Parquet

The **starfish-events** plugin intercepts JSON event-batch pushes on the server
and encodes them as Apache Parquet files written directly to the configured object
store. No JSON is persisted — the collection stores Parquet only.

This is the server-side complement to the [Parquet & DuckDB](/analytics/parquet-duckdb)
client-push model. Use the events plugin when:

- Events are produced by a SunGlasses (or compatible) analytics adapter, and
- You want the server to handle encoding rather than the client.

```
Analytics client       Starfish Server (+ events plugin)       Object Store (e.g. S3)
────────────────        ─────────────────────────────────       ──────────────────────
push JSON batch  ──►  intercept → encode Parquet → putBytes ──► events/app/<batchId>.parquet
                 ◄──  { hash }
```

---

## Setup

### TypeScript

```ts
import { S3ObjectStore } from "@drakkar.software/starfish-server/s3"
import { createSyncRouter } from "@drakkar.software/starfish-server"
import { createEventsServerPlugin } from "@drakkar.software/starfish-events"

const store = new S3ObjectStore({ bucket: "my-bucket" /* … */ })

const eventsPlugin = createEventsServerPlugin({
  store,
  collection: "events",
  storagePath: "events/{app}/{batchId}",
})

const syncRouter = createSyncRouter({
  store,
  config: {
    version: 1,
    collections: [
      {
        name: "events",
        storagePath: "events/{app}/{batchId}",
        readRoles: ["admin"],
        writeRoles: ["public"],
        encryption: "none",
        allowedMimeTypes: ["application/json"],
        maxBodyBytes: 8_000_000,
      },
    ],
  },
  plugins: [eventsPlugin],
})
```

### Python

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
                    allowed_mime_types=["application/json"],
                    max_body_bytes=8_000_000,
                )
            ],
        ),
        plugins=[plugin],
    )
)
```

---

## Collection requirement

The intercepted collection **must** be `application/json`-typed. A
Parquet-typed collection yields an empty body in `interceptPush` and the plugin
would encode empty files. Use `allowedMimeTypes: ["application/json"]` (TS) or
`allowed_mime_types: ["application/json"]` (Python).

---

## One file per batch

Parquet's column-footer format makes in-place append impractical. Each push
writes a unique file. DuckDB's glob `read_parquet('s3://…/**/*.parquet')` treats
all files under the prefix as one logical dataset — so you can query the full
history without knowing individual file names.

The plugin stamps every row with a `received_at` column (ISO-8601 UTC) set
server-side at ingest time.

---

## Batch id & incremental listing

The plugin — not the client — assigns the final `{batchId}` path segment: a
server-clock-derived, lexicographically-sortable id (13-digit epoch-ms + a
per-ms counter + a random suffix, e.g. `1782933157690-0000-735223`). The push
URL's `{batchId}` value is discarded; the client learns the real id later, by
listing.

This makes incremental sync possible: if the collection is `listable: true`
(TS) / `listable=True` (Python), `GET /list/<collection>/<app>` returns stored
batch ids in ascending lexicographic order — which, because the id is
server-clock-derived, is also chronological order. A dashboard or sync client
can persist the last-seen id and pass it back as `?after=<id>` on the next
poll to fetch only batches written since then, instead of re-listing from the
beginning every time.

A client-minted id can't provide that guarantee: batches are pushed from many
end-user devices with untrusted, possibly-skewed clocks, so a lexicographic
cursor over client timestamps could permanently miss a batch from a
clock-skewed-slow device. Ordering is guaranteed only *within one server
process* — multiple sync-server instances each mint their own monotonic
sequence.

---

## Pulling Parquet files

A `GET /pull/<collection>/<params>` request returns the stored Parquet file for
that key. The server sets `Content-Type: application/vnd.apache.parquet` and an
`ETag` header computed from the file contents. Conditional GETs (`If-None-Match`)
return `304 Not Modified` when the file hasn't changed.

This lets admin clients or internal tooling download raw Parquet batches over the
standard sync pull endpoint without any extra routes. `batchId` below is whatever
`GET /list/events/myapp` returned — not a value the pusher controls (see
[Batch id & incremental listing](#batch-id--incremental-listing) above):

```ts
// TypeScript
const res = await fetch("/pull/events/myapp/1782933157690-0000-735223", {
  headers: { Authorization: `Bearer ${adminToken}` },
})
const buf = await res.arrayBuffer()
// Pass to hyparquet, parquet-wasm, or save to disk
```

```python
# Python
import httpx
r = httpx.get("/pull/events/myapp/1782933157690-0000-735223", headers={"Authorization": f"Bearer {admin_token}"})
parquet_bytes = r.content  # write to file or pass to pyarrow
```

If no batch has been pushed for that key yet, the response falls through to the
normal sync-protocol JSON response (200 with empty data).

---

## Storage backends

The plugin writes Parquet bytes through the abstract `ObjectStore` /
`AbstractObjectStore` interface — **no direct S3 dependency in the events package
itself**. Any store that supports binary writes (`putBytes` / `put_bytes`) can receive
the files.

| Backend | Ingest (write Parquet) | DuckDB query |
|---|---|---|
| `S3ObjectStore` | ✓ | ✓ — `read_parquet('s3://…/**/*.parquet')` + `httpfs` + `SET s3_*` |
| `FilesystemObjectStore` | ✓ | ✓ — `read_parquet('/data/root/…/**/*.parquet')`, no credentials needed |
| `MemoryObjectStore` | ✓ (dev / tests) | ✗ — no file path to give DuckDB; testing only |
| Custom / `CustomObjectStore` | ✓ if `putBytes` / `put_bytes` is implemented | depends — DuckDB needs a URI it can reach for those bytes |

> **Takeaway:** ingest is backend-agnostic. The DuckDB query examples below assume S3.
> For `FilesystemObjectStore`, replace the `s3://` URI with the local file path on
> disk — no `httpfs` extension or credentials required. Support for a
> `duckdbReadParquetSql`-equivalent helper for non-S3 backends is a possible future
> addition.

---

## Querying with DuckDB

### S3-backed stores

```sql
-- Count events by type across all batches for one app
SELECT event_type, COUNT(*) AS n
FROM read_parquet('s3://my-bucket/events/myapp/**/*.parquet')
GROUP BY event_type
ORDER BY n DESC;

-- Time-bucket: events per hour (last 7 days)
SELECT
  time_bucket(INTERVAL '1 hour', received_at::TIMESTAMPTZ) AS hour,
  COUNT(*) AS n
FROM read_parquet('s3://my-bucket/events/myapp/**/*.parquet')
WHERE received_at >= now() - INTERVAL '7 days'
GROUP BY 1
ORDER BY 1;
```

> Requires the DuckDB `httpfs` extension and S3 credentials configured via
> `SET s3_region`, `SET s3_access_key_id`, etc. See the
> [Parquet & DuckDB](/analytics/parquet-duckdb) page for S3 setup.

### Filesystem-backed stores

For servers using `FilesystemObjectStore`, Parquet files land on the local filesystem.
Query them directly — no `httpfs` or credentials required:

```sql
-- Replace /data/root with the root path passed to FilesystemObjectStore
SELECT event_type, COUNT(*) AS n
FROM read_parquet('/data/root/events/myapp/**/*.parquet')
GROUP BY event_type
ORDER BY n DESC;
```

---

## Package reference

- TypeScript: [`@drakkar.software/starfish-events`](/packages/typescript/events)
- Python: [`starfish-events`](/packages/python/events)
