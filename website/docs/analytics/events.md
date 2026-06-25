---
sidebar_position: 2
---

# Events Plugin — JSON push → Parquet

The **starfish-events** plugin intercepts JSON event-batch pushes on the server
and encodes them as Apache Parquet files written directly to S3. No JSON is
persisted — the collection stores Parquet only.

This is the server-side complement to the [Parquet & DuckDB](/analytics/parquet-duckdb)
client-push model. Use the events plugin when:

- Events are produced by a SunGlasses (or compatible) analytics adapter, and
- You want the server to handle encoding rather than the client.

```
Analytics client       Starfish Server (+ events plugin)       S3
────────────────        ─────────────────────────────────       ──
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
writes a unique file (the `{batchId}` placeholder resolves to the UUID in the
push URL). DuckDB's glob `read_parquet('s3://…/**/*.parquet')` treats all files
under the prefix as one logical dataset — so you can query the full history
without knowing individual file names.

The plugin stamps every row with a `received_at` column (ISO-8601 UTC) set
server-side at ingest time.

---

## Querying with DuckDB

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

---

## Package reference

- TypeScript: [`@drakkar.software/starfish-events`](/packages/typescript/events)
- Python: [`starfish-events`](/packages/python/events)
