---
sidebar_position: 1
---

# Parquet & DuckDB

Starfish supports **Parquet** as a first-class collection type.  Clients generate Apache Parquet files locally, push them through the server, and the server stores them verbatim on S3.  [DuckDB](https://duckdb.org) then queries those files **directly from S3** via its `httpfs` extension — bypassing the server entirely for reads.

```
Client                 Starfish Server          S3 / MinIO
──────                 ───────────────          ──────────
pushParquet()  ──POST──►  auth + MIME check       putBytes(key, bytes)
               ◄──hash──  (cap-cert write)       ──────────────────────►
                                                       │
DuckDB                                                 │
read_parquet('s3://…') ─────────────────────────────►  GetObject
```

> **Prerequisites:** [Binary Collections](/data-modeling/binary-collections), [StarfishClient](/client-core/starfish-client)

---

## Why Parquet on S3?

- **Column-oriented analytics** — DuckDB can read only the columns and row-groups it needs, scanning gigabytes efficiently from object storage.
- **No server dependency** for reads — analysts run `read_parquet('s3://…')` without a running Starfish server.
- **Standard format** — any tool that speaks Parquet (pandas, polars, Arrow, Spark, …) can read the same files.
- **Controlled ingestion** — the server enforces MIME type, body-size limits, and cap-cert authentication on writes, keeping data quality checks in one place.

---

## Server configuration

Use `createParquetCollection()` (TypeScript) or `create_parquet_collection()` (Python) to build the `CollectionConfig`. The helpers set the right defaults — the underlying transport is the existing binary-collection machinery.

### TypeScript

```ts
import {
  createParquetCollection,
  createSyncRouter,
  type SyncConfig,
} from "@drakkar.software/starfish-server"

const col = createParquetCollection({
  name: "datasets",
  storagePath: "datasets/{owner}/{dataset}",
  read: "public",         // DuckDB reads S3 directly — no auth on reads
  write: "authenticated", // Only cap-cert holders may push Parquet files
  rateLimit: "none",      // No rate limit (omits the rateLimit field entirely)
})

const config: SyncConfig = { version: 1, collections: [col] }
```

### Python

```python
from starfish_server import create_parquet_collection, SyncConfig

col = create_parquet_collection(
    name="datasets",
    storage_path="datasets/{owner}/{dataset}",
    read="public",          # DuckDB reads S3 directly — no auth on reads
    write="authenticated",  # Only cap-cert holders may push Parquet files
    rate_limit="none",      # No rate limit
)

config = SyncConfig(version=1, collections=[col])
```

### `read` / `write` options

Both `read` and `write` accept the same set of values — independently:

| Value | Roles generated | Effect |
|---|---|---|
| `"public"` (default for `read`) | `["public"]` | Anyone may call this endpoint |
| `"authenticated"` (default for `write`) | `["cap:read:<name>"]` / `["cap:write:<name>"]` | Requires a valid cap-cert |
| `"none"` | n/a | Endpoint disabled (`pullOnly` / `pushOnly`) |
| `string[]` | verbatim | Custom role list |

> **Note:** Both `read` and `write` may not both be `"none"` — that would produce an inaccessible collection.

### Why `encryption: "none"` is forced

`createParquetCollection` always sets `encryption: "none"`. Delegated encryption (`"delegated"`) stores AES-256-GCM ciphertext on S3; DuckDB cannot decrypt it.  If you need encrypted Parquet, encrypt the bytes yourself before calling `pushParquet` / `push_parquet` and decrypt after `pullParquet` / `pull_parquet`.

### Rate limiting

Pass any `CollectionRateLimitConfig` object to `rateLimit` to enable per-action limits:

```ts
rateLimit: {
  push: { windowMs: 60_000, maxRequests: 100 },
  pull: { windowMs: 60_000, maxRequests: 1000 },
}
```

Omit `rateLimit` (or pass `"none"`) to leave the collection unmetered.

---

## S3 key scheme

The S3 object key is the resolved `storagePath` template.  For `storagePath: "datasets/{owner}/{dataset}"` and a push to `/push/datasets/alice/q1.parquet`, the S3 key is:

```
datasets/alice/q1.parquet
```

Use `resolveDocumentKey()` to derive keys in client code and tests:

```ts
import { resolveDocumentKey } from "@drakkar.software/starfish-server"

const key = resolveDocumentKey("datasets/{owner}/{dataset}", {
  owner: "alice",
  dataset: "q1.parquet",
})
// → "datasets/alice/q1.parquet"
```

```python
from starfish_server import resolve_document_key

key = resolve_document_key("datasets/{owner}/{dataset}", {"owner": "alice", "dataset": "q1.parquet"})
# → "datasets/alice/q1.parquet"
```

---

## Partitioning and `listable`

When the **last segment** of `storagePath` is a `{param}`, `createParquetCollection` automatically sets `listable: true`.  This exposes a `GET /list/…` endpoint that returns the stored file names — useful for discovery and DuckDB globs.

Partition by date, user, or any dimension that matters for your queries:

```
storagePath: "datasets/{owner}/{date}"   → s3://bucket/datasets/alice/2024-01-15.parquet
storagePath: "reports/{team}/{report}"   → s3://bucket/reports/eng/weekly.parquet
```

---

## Pushing Parquet from the client

### TypeScript

`pushParquet` is a thin wrapper over `pushBlob` that fixes `Content-Type` to `application/vnd.apache.parquet`:

```ts
import { StarfishClient } from "@drakkar.software/starfish-client"

// Use your preferred Parquet library (parquet-wasm, Arrow, DuckDB-WASM, …)
const parquetBytes: ArrayBuffer = await generateParquet(rows)

const result = await client.pushParquet(
  `/push/datasets/alice/q1-2024.parquet`,
  parquetBytes,
)
console.log("stored hash:", result.hash)
```

### Python

```python
from starfish_sdk import StarfishClient

# Use your preferred Parquet library (pyarrow, polars, duckdb, …)
parquet_bytes: bytes = generate_parquet(rows)

async with StarfishClient(base_url, auth=cap_provider) as client:
    result = await client.push_parquet(
        "/push/datasets/alice/q1-2024.parquet",
        parquet_bytes,
    )
    print("stored hash:", result.hash)
```

The server accepts `application/vnd.apache.parquet`, `application/x-parquet`, and `application/octet-stream` (the full `PARQUET_MIME_TYPES` accept-list), so Parquet writers that emit `octet-stream` work out of the box.

---

## Querying with DuckDB

Use `duckdbReadParquetSql()` / `duckdb_read_parquet_sql()` to generate the DuckDB SQL. No DuckDB dependency is required in the server package — you run the SQL yourself.

### TypeScript

```ts
import {
  duckdbReadParquetSql,
  resolveDocumentKey,
} from "@drakkar.software/starfish-server"
import type { S3StorageOptions } from "@drakkar.software/starfish-server/s3"

const s3: S3StorageOptions = {
  endpoint: "http://localhost:9000",   // or "https://s3.amazonaws.com"
  bucket: "starfish",
  accessKeyId: "minio",
  secretAccessKey: "minio123",
  forcePathStyle: true,                // true for MinIO / false for AWS
}

// Single file
const key = resolveDocumentKey("datasets/{owner}/{dataset}", {
  owner: "alice",
  dataset: "q1-2024.parquet",
})
const { uri, sql } = duckdbReadParquetSql({ s3, key })
console.log(sql)
// INSTALL httpfs;
// LOAD httpfs;
// SET s3_endpoint='localhost:9000';
// SET s3_access_key_id='minio';
// ...
// SELECT * FROM read_parquet('s3://starfish/datasets/alice/q1-2024.parquet');

// Glob over all of alice's datasets
const prefixKey = resolveDocumentKey("datasets/{owner}", { owner: "alice" })
const { sql: globSql } = duckdbReadParquetSql({ s3, key: prefixKey, glob: true })
// → SELECT * FROM read_parquet('s3://starfish/datasets/alice/*.parquet');
```

### Python

```python
from starfish_server import duckdb_read_parquet_sql, resolve_document_key
from starfish_server.storage.s3 import S3StorageOptions

s3 = S3StorageOptions(
    endpoint="http://localhost:9000",
    bucket="starfish",
    access_key_id="minio",
    secret_access_key="minio123",
)

# Single file
key = resolve_document_key("datasets/{owner}/{dataset}", {"owner": "alice", "dataset": "q1.parquet"})
result = duckdb_read_parquet_sql(s3=s3, key=key)
print(result.sql)

# Glob over all of alice's datasets (force_path_style=True for MinIO)
prefix = resolve_document_key("datasets/{owner}", {"owner": "alice"})
result = duckdb_read_parquet_sql(s3=s3, key=prefix, glob=True)
# → SELECT * FROM read_parquet('s3://starfish/datasets/alice/*.parquet');
```

### Running the SQL

```bash
# DuckDB CLI
duckdb -c "$(your_app print-duckdb-sql)"

# Python
import duckdb
conn = duckdb.connect()
conn.execute(sql)
df = conn.fetchdf()
```

---

## DuckDB `httpfs` settings reference

| DuckDB setting | Derived from |
|---|---|
| `s3_endpoint` | `endpoint` host:port |
| `s3_access_key_id` | `accessKeyId` / `access_key_id` |
| `s3_secret_access_key` | `secretAccessKey` / `secret_access_key` |
| `s3_region` | `region` (default `"us-east-1"`) |
| `s3_url_style` | `forcePathStyle=true` → `'path'`; `false` → `'vhost'` |
| `s3_use_ssl` | `endpoint` scheme: `https` → `true`; `http` → `false` |

---

## Security note

Reads bypass the Starfish server — they hit S3 directly.  With `read: "public"`, DuckDB queries require only valid S3 credentials (or a public bucket) — **not** a Starfish cap-cert.

- Use `read: "public"` for analytics data that may be shared broadly.
- Use `read: "authenticated"` when pull access should also be cap-cert gated (e.g. `client.pullParquet()` for server-mediated downloads).
- In both cases, **write** access is authenticated by default, keeping ingestion controlled.

If S3 bucket is private, readers must supply the same S3 credentials via `SET s3_access_key_id` / `SET s3_secret_access_key` in DuckDB, or assume the role / IAM profile that has `GetObject` permission.

---

## MIME type constants

```ts
// TypeScript
import { PARQUET_MIME_TYPE, PARQUET_MIME_TYPES } from "@drakkar.software/starfish-client"
// or from "@drakkar.software/starfish-server"

// PARQUET_MIME_TYPE  → "application/vnd.apache.parquet"
// PARQUET_MIME_TYPES → ["application/vnd.apache.parquet", "application/x-parquet", "application/octet-stream"]
```

```python
# Python
from starfish_sdk import PARQUET_MIME_TYPE, PARQUET_MIME_TYPES
# or from starfish_protocol.constants import PARQUET_MIME_TYPE, PARQUET_MIME_TYPES
```

---

## Related

- [Binary Collections](/data-modeling/binary-collections) — the underlying storage mechanism
- [StarfishClient](/client-core/starfish-client) — `pushParquet` / `pullParquet` method signatures
- [Storage](/server/storage) — configuring S3ObjectStore
- [Rate Limiting](/server/rate-limiting) — per-action rate limits on Parquet collections
