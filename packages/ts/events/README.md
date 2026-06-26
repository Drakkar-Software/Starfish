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
   Parquet and written via `store.putBytes`. The default JSON document write is
   short-circuited — **no JSON is persisted alongside the Parquet**.

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

## API

### `createEventsServerPlugin(opts): ServerPlugin`

| Option | Type | Description |
|---|---|---|
| `store` | `ObjectStore` | Object store with `putBytes`. Pass the same instance as `createSyncRouter`. |
| `collection` | `string` | Name of the collection to intercept (e.g. `"events"`). |
| `storagePath` | `string` | Storage-path template for the Parquet key. Supports `{param}` placeholders from the push URL. The `.parquet` extension is appended automatically if absent. |

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
