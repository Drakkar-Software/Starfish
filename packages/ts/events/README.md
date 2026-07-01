# @drakkar.software/starfish-events

Starfish server plugin that intercepts JSON event-batch pushes and encodes them as
[Apache Parquet](https://parquet.apache.org/) files written to any configured object
store — S3, filesystem, memory, or custom. The plugin has no direct S3 dependency;
it writes through the abstract `ObjectStore.putBytes` interface. The DuckDB query
examples below use S3; see [Storage backends](/analytics/events#storage-backends) for
non-S3 alternatives.

Mirrors [`starfish-events`](../python/events) (Python) with identical Parquet
encoding — both are locked to the same test vectors.

## Install

```bash
npm install @drakkar.software/starfish-events
```

## How it works

1. Register a JSON-typed collection (`allowedMimeTypes: ["application/json"]`) in your
   `SyncConfig`.
2. Attach `createEventsServerPlugin` to `createSyncRouter`.
3. Each push to that collection is intercepted: the JSON event batch is encoded as
   Parquet and written via `store.putBytes`, at a **server-assigned batch id**
   (see [Batch id](#batch-id) below) — not the client's. The default JSON document
   write is short-circuited — **no JSON is persisted alongside the Parquet**.

One Parquet file is written per push (one file per batch). For S3-backed stores,
DuckDB's `read_parquet('s3://…/**/*.parquet')` glob treats all files under the prefix
as one logical dataset.

## Usage

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
        allowedMimeTypes: ["application/json"],  // ← JSON-typed, not Parquet
        maxBodyBytes: 8_000_000,
      },
    ],
  },
  plugins: [eventsPlugin],
})
```

## Batch id

The plugin — not the client — assigns the final `{batchId}` path segment: a
server-clock-derived, lexicographically-sortable id (13-digit epoch-ms + a
per-ms counter + a random suffix, e.g. `1782933157690-0000-735223`). The
client's push URL still carries a `{batchId}` placeholder value, but it's
discarded.

This matters for **listing**: if the collection is also `listable: true`,
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

```ts
// batchId here is whatever GET /list/events/myapp returned — not a value the
// pusher controls (see "Batch id" above).
const res = await fetch("/pull/events/myapp/1782933157690-0000-735223")
// res.headers.get("content-type") === "application/vnd.apache.parquet"
const parquetBytes = await res.arrayBuffer()
```

If no batch was pushed for that key yet, the response falls through to the normal
sync-protocol JSON response (200 with empty data).

## API

### `createEventsServerPlugin(opts): ServerPlugin`

| Option | Type | Description |
|---|---|---|
| `store` | `ObjectStore` | Object store with `putBytes` / `getBytes`. Pass the same instance as `createSyncRouter`. |
| `collection` | `string` | Name of the collection to intercept (e.g. `"events"`). |
| `storagePath` | `string` | Storage-path template for the Parquet key. Supports `{param}` placeholders from the push/pull URL, except the **last** segment (also required to be a `{param}`), which is always overridden with a server-assigned sortable batch id — see [Batch id](#batch-id). The `.parquet` extension is appended automatically if absent. |

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
