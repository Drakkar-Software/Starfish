/**
 * Starfish Parquet / DuckDB example (TypeScript).
 *
 * Demonstrates:
 *   1. Configuring a server with a Parquet collection (public read, authed write).
 *   2. Pushing a Parquet file from the client via pushParquet().
 *   3. Generating the DuckDB SQL to query the stored Parquet from S3.
 *
 * Run (in-memory store, no real S3 needed for the push demo):
 *   npx tsx examples/ts/parquet-duckdb.ts
 *
 * For real S3/MinIO, swap MemoryObjectStore for S3ObjectStore (see comment below).
 */

import { webcrypto } from "node:crypto"
import { Hono } from "hono"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import {
  createSyncRouter,
  createCapCertRoleResolver,
  createInMemoryNonceCache,
  createInMemoryRevocationStore,
  MemoryObjectStore,
  createParquetCollection,
  duckdbReadParquetSql,
  resolveDocumentKey,
  PARQUET_MIME_TYPE,
} from "@drakkar.software/starfish-server"
import { StarfishClient } from "@drakkar.software/starfish-client"

// ── Platform setup (Node.js) ─────────────────────────────────────────────────
configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (d: Uint8Array) => Buffer.from(d).toString("base64"),
    decode: (s: string) => new Uint8Array(Buffer.from(s, "base64")),
  },
})

// ── S3 options (swap MemoryObjectStore for S3ObjectStore in production) ───────
const S3_OPTS = {
  endpoint: "http://localhost:9000",
  bucket: "starfish",
  accessKeyId: "minio",
  secretAccessKey: "minio123",
  forcePathStyle: true,
}
// To use real S3/MinIO:
//   import { S3ObjectStore } from "@drakkar.software/starfish-server/s3"
//   const store = new S3ObjectStore(S3_OPTS)
const store = new MemoryObjectStore(new Map())

// ── Parquet collection ────────────────────────────────────────────────────────
//
// createParquetCollection() builds a CollectionConfig preset for
// DuckDB-readable Parquet files:
//   • allowedMimeTypes = PARQUET_MIME_TYPES (accepts all common Parquet MIME variants)
//   • encryption: "none"  (delegated encryption stores ciphertext; DuckDB can't decode it)
//   • listable: true      (last storagePath segment is {dataset} → DuckDB can glob *.parquet)
//
// Auth levers (each independent):
//   read:  "public"        → anonymous DuckDB S3 reads bypass the server
//   read:  "authenticated" → only cap-cert holders may pull
//   read:  "none"          → pull endpoint disabled (write-only ingest)
//   write: "authenticated" → cap-cert required to push Parquet files
//   write: "public"        → anyone can push (open ingest)
//   write: string[]        → custom role list

const col = createParquetCollection({
  name: "datasets",
  storagePath: "datasets/{owner}/{dataset}",
  read: "public",         // DuckDB reads directly from S3 — no auth needed
  write: "authenticated", // Only cap-cert holders may push Parquet files
  rateLimit: "none",      // No rate limit (default)
  maxBodyBytes: 256 * 1024 * 1024,
})

console.log("Collection config:", JSON.stringify(col, null, 2))

// ── Server ───────────────────────────────────────────────────────────────────
const roleResolver = createCapCertRoleResolver({
  nonceCache: createInMemoryNonceCache(),
  revocationStore: createInMemoryRevocationStore(),
})

const app = new Hono()
app.route("/v1", createSyncRouter({
  store,
  config: { version: 1, collections: [col] },
  roleResolver,
}))

// In production: serve with @hono/node-server or your preferred runtime.
// For this demo we use app.request() to simulate HTTP locally.

// ── Tiny fake Parquet buffer (replace with your parquet library output) ────────
// A valid Parquet file starts and ends with the magic bytes "PAR1".
// In production, use a library like parquet-wasm, Apache Arrow, or DuckDB
// to generate real Parquet bytes from your data.
function makeParquetBytes(label: string): Uint8Array {
  const magic = new TextEncoder().encode("PAR1")
  const body = new TextEncoder().encode(`FAKE_PARQUET_BODY:${label}`)
  const buf = new Uint8Array(magic.length + body.length + magic.length)
  buf.set(magic, 0)
  buf.set(body, magic.length)
  buf.set(magic, magic.length + body.length)
  return buf
}

// ── Push Parquet bytes ────────────────────────────────────────────────────────
async function demo() {
  const parquetBytes = makeParquetBytes("q1-2024")

  // Simulate an authenticated push via app.request() (no real HTTP server needed).
  // In production, use StarfishClient with a capProvider for cap-cert auth.
  const pushPath = "/v1/push/datasets/alice/q1-2024.parquet"
  const pushRes = await app.request(pushPath, {
    method: "POST",
    headers: {
      "Content-Type": PARQUET_MIME_TYPE,
      // In production: add cap-cert auth headers via StarfishClient.pushParquet()
    },
    body: parquetBytes,
  })

  if (!pushRes.ok) {
    console.error("Push failed:", pushRes.status, await pushRes.text())
    // Note: 403 is expected here because we have no cap-cert in this demo.
    // Run with a real client + capProvider for an authenticated push.
    console.log("\n─── TIP ───────────────────────────────────────────────────")
    console.log("Use StarfishClient.pushParquet() with a capProvider for real auth:")
    console.log('  const client = new StarfishClient({ baseUrl, capProvider })')
    console.log('  await client.pushParquet("/push/datasets/alice/q1-2024.parquet", bytes)')
    console.log("───────────────────────────────────────────────────────────\n")
  } else {
    const { hash } = await pushRes.json()
    console.log("✓ Pushed Parquet file. SHA-256 hash:", hash)
  }

  // ── Derive the S3 key and generate DuckDB SQL ──────────────────────────────
  //
  // resolveDocumentKey() maps the storagePath template + params to the exact
  // S3 object key (same key the server uses in putBytes(key, bytes)).
  const key = resolveDocumentKey("datasets/{owner}/{dataset}", {
    owner: "alice",
    dataset: "q1-2024.parquet",
  })
  console.log("\n── S3 key:", key)

  // duckdbReadParquetSql() generates all the DuckDB SQL you need:
  const { uri, sql } = duckdbReadParquetSql({ s3: S3_OPTS, key })
  console.log("\n── S3 URI:", uri)
  console.log("\n── DuckDB SQL (run in DuckDB CLI or via the duckdb npm package):")
  console.log("─".repeat(60))
  console.log(sql)
  console.log("─".repeat(60))

  // ── Glob over all of alice's datasets ─────────────────────────────────────
  const prefixKey = resolveDocumentKey("datasets/{owner}", { owner: "alice" })
  const { sql: globSql } = duckdbReadParquetSql({ s3: S3_OPTS, key: prefixKey, glob: true })
  console.log("\n── Glob query (all datasets for alice):")
  console.log("─".repeat(60))
  console.log(globSql)
  console.log("─".repeat(60))

  console.log("\nDone. In production:")
  console.log("  1. Run the server with S3ObjectStore (swap MemoryObjectStore above)")
  console.log("  2. Use StarfishClient.pushParquet() with a capProvider")
  console.log("  3. Run the generated DuckDB SQL to query the stored Parquet files")
}

demo().catch(console.error)
