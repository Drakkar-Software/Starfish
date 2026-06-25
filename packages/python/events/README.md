# starfish-events

Starfish server plugin that intercepts JSON event-batch pushes and encodes them as
[Apache Parquet](https://parquet.apache.org/) files written directly to the object
store (typically S3).

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
   Parquet and written via `store.put_bytes`. The default JSON document write is
   short-circuited — **no JSON is persisted alongside the Parquet**.

One Parquet file is written per push (one file per batch). DuckDB's
`read_parquet('s3://…/**/*.parquet')` glob treats all files under the prefix as one
logical dataset.

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

## API

### `create_events_server_plugin(*, store, collection, storage_path) -> ServerPlugin`

| Parameter | Type | Description |
|---|---|---|
| `store` | `AbstractObjectStore` | Object store with `put_bytes`. Pass the same instance as `create_sync_router`. |
| `collection` | `str` | Name of the collection to intercept (e.g. `"events"`). |
| `storage_path` | `str` | Storage-path template for the Parquet key. Supports `{param}` placeholders from the push URL. The `.parquet` extension is appended automatically if absent. |

The plugin adds `received_at` (ISO-8601 UTC) to every event row before encoding.

## Querying with DuckDB

```sql
SELECT event_type, COUNT(*) AS n
FROM read_parquet('s3://my-bucket/events/myapp/**/*.parquet')
GROUP BY event_type
ORDER BY n DESC;
```

See [Analytics — Events & Parquet](/analytics/events) for the full guide.
