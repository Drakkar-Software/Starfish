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

> **Note on storage:** the Parquet write path (via `pushParquet` or the events plugin)
> is **store-agnostic** — files land in whatever `ObjectStore` you configure (S3,
> filesystem, memory, or custom). The `read_parquet('s3://…')` recipes on this page
> are specific to S3-backed stores. If you use `FilesystemObjectStore`, substitute a
> local file path and omit `httpfs`; see [Events plugin — Storage backends](/analytics/events#storage-backends)
> for the full backend matrix.

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

`createParquetCollection` always sets `encryption: "none"`. Delegated encryption (`"delegated"`) stores AES-256-GCM ciphertext on S3; DuckDB cannot decrypt it.  If you need E2EE Parquet, use `createSealedParquetCollection` — see [E2EE Parquet](#e2ee-parquet-createsealed) below.

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

---

## E2EE Parquet (`createSealedParquetCollection`) {#e2ee-parquet-createsealed}

Use `createSealedParquetCollection` when **privacy is more important than DuckDB-over-S3 queryability**. The client AES-256-GCM-seals the Parquet bytes under the space keyring CEK (AAD bound to the storage path) before pushing; the server and S3 bucket only ever store opaque ciphertext.

```
Client                          Starfish Server          S3 / MinIO
──────                          ───────────────          ──────────
sealAndPushBlob(enc, parquetBytes)  ──POST──►  auth + MIME check  putBytes(key, ciphertext)
                                ◄──hash──  (cap-cert write)      ──────────────────────►
                                                                        │ (ciphertext only)
pullAndOpenBlob(enc)  ◄──────────────────────────────────────────  GetObject
     │
     ▼
DuckDB-WASM (client-side, after unsealing)
```

**Trade-off:** the stored bytes are NOT valid Parquet files — DuckDB `read_parquet('s3://…')` will fail because it reads raw ciphertext. Clients must pull → unseal → load into DuckDB-WASM (or another in-process engine) to query.

### Server configuration

```ts
import {
  createSealedParquetCollection,
} from "@drakkar.software/starfish-server"

const col = createSealedParquetCollection({
  name: "private-datasets",
  storagePath: "spaces/{spaceId}/objects/parquet-enc/{objectId}",
  read: ["space:member"],   // only space members may read
  write: ["space:member"],  // only space members may write
  maxBodyBytes: 67_108_864, // 64 MiB
})
```

```python
from starfish_server import create_sealed_parquet_collection

col = create_sealed_parquet_collection(
    name="private-datasets",
    storage_path="spaces/{spaceId}/objects/parquet-enc/{objectId}",
    read=["space:member"],
    write=["space:member"],
    max_body_bytes=67_108_864,
)
```

The factory has the **same option semantics** as `createParquetCollection` (`read`/`write` access modes, `rateLimit`, `maxBodyBytes`, `cacheDurationMs`, auto-`listable` from path), with two differences:

- `read` defaults to `"authenticated"` instead of `"public"` — E2EE data should not be world-downloadable by default.
- `allowedMimeTypes` is `["application/octet-stream"]` instead of `PARQUET_MIME_TYPES` — the server stores opaque ciphertext, not readable Parquet.

### Client seal/unseal

Use `sealAndPushBlob` and `pullAndOpenBlob` from `@drakkar.software/starfish-client` with a `KeyringEncryptor` (from `@drakkar.software/starfish-keyring`):

```ts
import {
  sealAndPushBlob,
  pullAndOpenBlob,
} from "@drakkar.software/starfish-client"

// Obtain a KeyringEncryptor from the space keyring (omitted for brevity)
const enc: ByteSealer = createKeyringEncryptor(keyring, kemKeys, { trustedAdders })

// Seal and upload (objectId is any unique ID you mint for this file)
const objectId = "my-dataset-v1"
const storagePath = `spaces/${spaceId}/objects/parquet-enc/${objectId}`
await sealAndPushBlob(client, enc, `/push/${storagePath}`, parquetBytes, {
  aad: storagePath, // MUST be stable — used for back-compat on subsequent opens
})

// Pull and unseal
const plaintext = await pullAndOpenBlob(client, enc, `/pull/${storagePath}`, {
  aad: storagePath,
})
// plaintext is the original Parquet bytes — load into DuckDB-WASM to query
```

**AAD:** the `aad` value is bound into the AES-GCM tag; mismatching it on open throws a decryption error. When `aad` is omitted, both `sealAndPushBlob` and `pullAndOpenBlob` derive it from the document key (path with `/push/` or `/pull/` stripped), so the default round-trips correctly for matching push/pull path pairs. Always pass an explicit, stable `aad` when you need to preserve access to already-sealed blobs across upgrades.

### When to use which factory

| Requirement | Use |
|---|---|
| Server-side / S3-direct DuckDB queries | `createParquetCollection` |
| E2EE (server never sees plaintext) | `createSealedParquetCollection` + `sealAndPushBlob`/`pullAndOpenBlob` |
| E2EE **and** DuckDB-over-S3 | Not currently supported (Parquet Modular Encryption is not implemented) |

---

## Related

- [Binary Collections](/data-modeling/binary-collections) — the underlying storage mechanism
- [StarfishClient](/client-core/starfish-client) — `pushParquet` / `pullParquet` / `sealAndPushBlob` / `pullAndOpenBlob`
- [Storage](/server/storage) — configuring S3ObjectStore
- [Rate Limiting](/server/rate-limiting) — per-action rate limits on Parquet collections
