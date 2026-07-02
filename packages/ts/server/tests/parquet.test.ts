import { describe, it, expect } from "vitest"
import { createParquetCollection, createSealedParquetCollection, duckdbReadParquetSql, resolveDocumentKey } from "../src/parquet.js"
import { PARQUET_MIME_TYPE, PARQUET_MIME_TYPES } from "@drakkar.software/starfish-protocol"
import { validateConfig } from "../src/config/validate.js"
import { createSyncRouter, type SyncRouterOptions, type AuthResult } from "../src/router/route-builder.js"
import { MemoryObjectStore } from "../src/storage/memory.js"
import type { SyncConfig } from "../src/config/schema.js"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { webcrypto } from "node:crypto"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

// Parquet magic bytes: PAR1 at start and end of a valid file
const PARQUET_BYTES = Buffer.concat([
  Buffer.from("PAR1"),
  Buffer.alloc(100, 0),
  Buffer.from("PAR1"),
])

// ---------------------------------------------------------------------------
// MIME constants
// ---------------------------------------------------------------------------

describe("PARQUET_MIME_TYPE and PARQUET_MIME_TYPES", () => {
  it("PARQUET_MIME_TYPE is the canonical vnd MIME string", () => {
    expect(PARQUET_MIME_TYPE).toBe("application/vnd.apache.parquet")
  })

  it("PARQUET_MIME_TYPES includes all Parquet variants", () => {
    expect(PARQUET_MIME_TYPES).toContain("application/vnd.apache.parquet")
    expect(PARQUET_MIME_TYPES).toContain("application/x-parquet")
    expect(PARQUET_MIME_TYPES).toContain("application/octet-stream")
  })
})

// ---------------------------------------------------------------------------
// resolveDocumentKey
// ---------------------------------------------------------------------------

describe("resolveDocumentKey", () => {
  it("substitutes a single param", () => {
    expect(resolveDocumentKey("users/{identity}/notes", { identity: "alice" })).toBe(
      "users/alice/notes",
    )
  })

  it("substitutes multiple params", () => {
    expect(
      resolveDocumentKey("datasets/{owner}/{dataset}", { owner: "alice", dataset: "q1.parquet" }),
    ).toBe("datasets/alice/q1.parquet")
  })

  it("leaves unknown params unsubstituted", () => {
    expect(resolveDocumentKey("datasets/{owner}/{dataset}", { owner: "alice" })).toBe(
      "datasets/alice/{dataset}",
    )
  })
})

// ---------------------------------------------------------------------------
// createParquetCollection — config factory
// ---------------------------------------------------------------------------

describe("createParquetCollection", () => {
  it("defaults: public read, authenticated write, no rate limit, 256 MB", () => {
    const col = createParquetCollection({
      name: "datasets",
      storagePath: "datasets/{owner}/{dataset}",
    })
    expect(col.name).toBe("datasets")
    expect(col.readRoles).toEqual(["public"])
    expect(col.writeRoles).toEqual(["cap:write:datasets"])
    expect(col.encryption).toBe("none")
    expect(col.maxBodyBytes).toBe(256 * 1024 * 1024)
    expect(col.allowedMimeTypes).toEqual([...PARQUET_MIME_TYPES])
    expect(col.rateLimit).toBeNull()
  })

  it("forces encryption:'none'", () => {
    const col = createParquetCollection({ name: "x", storagePath: "x/{id}", read: "public", write: "authenticated" })
    expect(col.encryption).toBe("none")
  })

  it("read:'public' → readRoles=['public']", () => {
    const col = createParquetCollection({ name: "x", storagePath: "x/{id}", read: "public", write: "authenticated" })
    expect(col.readRoles).toEqual(["public"])
    expect(col.pushOnly).toBeUndefined()
  })

  it("read:'authenticated' → readRoles=['cap:read:x']", () => {
    const col = createParquetCollection({ name: "x", storagePath: "x/{id}", read: "authenticated", write: "public" })
    expect(col.readRoles).toEqual(["cap:read:x"])
  })

  it("read:'none' → pushOnly:true, pull endpoint disabled", () => {
    const col = createParquetCollection({ name: "x", storagePath: "x/{id}", read: "none", write: "public" })
    expect(col.pushOnly).toBe(true)
    expect(col.pullOnly).toBeUndefined()
  })

  it("write:'public' → writeRoles=['public']", () => {
    const col = createParquetCollection({ name: "x", storagePath: "x/{id}", read: "public", write: "public" })
    expect(col.writeRoles).toEqual(["public"])
  })

  it("write:'authenticated' → writeRoles=['cap:write:x']", () => {
    const col = createParquetCollection({ name: "x", storagePath: "x/{id}", read: "public", write: "authenticated" })
    expect(col.writeRoles).toEqual(["cap:write:x"])
  })

  it("write:'none' → pullOnly:true, push endpoint disabled", () => {
    const col = createParquetCollection({ name: "x", storagePath: "x/{id}", read: "public", write: "none" })
    expect(col.pullOnly).toBe(true)
    expect(col.pushOnly).toBeUndefined()
  })

  it("read and write custom string[] — verbatim", () => {
    const col = createParquetCollection({
      name: "x",
      storagePath: "x/{id}",
      read: ["admin", "viewer"],
      write: ["admin"],
    })
    expect(col.readRoles).toEqual(["admin", "viewer"])
    expect(col.writeRoles).toEqual(["admin"])
  })

  it("throws when both read and write are 'none'", () => {
    expect(() =>
      createParquetCollection({ name: "x", storagePath: "x/{id}", read: "none", write: "none" }),
    ).toThrowError(/both read and write are "none"/)
  })

  it("auto-enables listable when last storagePath segment is a {param}", () => {
    const col = createParquetCollection({
      name: "x",
      storagePath: "datasets/{owner}/{file}",
    })
    expect(col.listable).toBe(true)
  })

  it("does NOT enable listable when last segment is not a {param}", () => {
    const col = createParquetCollection({
      name: "x",
      storagePath: "datasets/{owner}/summary",
    })
    expect(col.listable).toBeFalsy()
  })

  it("rateLimit:'none' → rateLimit:null on the config", () => {
    const col = createParquetCollection({ name: "x", storagePath: "x/{id}", rateLimit: "none" })
    expect(col.rateLimit).toBeNull()
  })

  it("rateLimit config object is forwarded verbatim", () => {
    const rl = { windowMs: 60_000, maxRequests: 10 }
    const col = createParquetCollection({ name: "x", storagePath: "x/{id}", rateLimit: rl })
    expect(col.rateLimit).toEqual(rl)
  })

  it("cacheDurationMs is forwarded", () => {
    const col = createParquetCollection({ name: "x", storagePath: "x/{id}", cacheDurationMs: 30_000 })
    expect(col.cacheDurationMs).toBe(30_000)
  })

  it("maxBodyBytes override", () => {
    const col = createParquetCollection({ name: "x", storagePath: "x/{id}", maxBodyBytes: 1024 })
    expect(col.maxBodyBytes).toBe(1024)
  })

  it("resulting config passes validateConfig", () => {
    const col = createParquetCollection({
      name: "datasets",
      storagePath: "datasets/{owner}/{dataset}",
    })
    const config: SyncConfig = { version: 1, collections: [col] }
    const errors = validateConfig(config)
    expect(errors).toEqual([])
  })

  it("read:none config passes validateConfig (pushOnly=true)", () => {
    const col = createParquetCollection({
      name: "ingest",
      storagePath: "ingest/{owner}/{file}",
      read: "none",
      write: "authenticated",
    })
    const errors = validateConfig({ version: 1, collections: [col] })
    expect(errors).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// duckdbReadParquetSql
// ---------------------------------------------------------------------------

const S3_MINIO = {
  endpoint: "http://localhost:9000",
  bucket: "my-bucket",
  accessKeyId: "minio",
  secretAccessKey: "minio123",
  forcePathStyle: true,
}

const S3_AWS = {
  endpoint: "https://s3.amazonaws.com",
  bucket: "prod-bucket",
  accessKeyId: "AKID",
  secretAccessKey: "secret",
  forcePathStyle: false,
  region: "eu-west-1",
}

describe("duckdbReadParquetSql", () => {
  it("returns correct uri for MinIO", () => {
    const { uri } = duckdbReadParquetSql({ s3: S3_MINIO, key: "datasets/alice/q1.parquet" })
    expect(uri).toBe("s3://my-bucket/datasets/alice/q1.parquet")
  })

  it("setupSql contains INSTALL and LOAD httpfs", () => {
    const { setupSql } = duckdbReadParquetSql({ s3: S3_MINIO, key: "k" })
    expect(setupSql).toContain("INSTALL httpfs")
    expect(setupSql).toContain("LOAD httpfs")
  })

  it("configSql sets endpoint, access key id, region, url_style, ssl — but NOT the secret", () => {
    const { configSql } = duckdbReadParquetSql({ s3: S3_MINIO, key: "k" })
    expect(configSql).toContain("SET s3_endpoint='localhost:9000'")
    expect(configSql).toContain("SET s3_access_key_id='minio'")
    expect(configSql).toContain("SET s3_region='us-east-1'")
    expect(configSql).toContain("SET s3_url_style='path'")
    expect(configSql).toContain("SET s3_use_ssl=false")
    // The secret access key must never appear in the redactable configSql.
    expect(configSql).not.toContain("s3_secret_access_key")
    expect(configSql).not.toContain("minio123")
  })

  it("secret access key is excluded from redactable sql/configSql, present in credentialSql/runnableSql", () => {
    const { configSql, credentialSql, sql, runnableSql } = duckdbReadParquetSql({ s3: S3_MINIO, key: "k" })
    // Redactable fields (safe to log) must not leak the secret.
    expect(configSql).not.toContain("minio123")
    expect(sql).not.toContain("minio123")
    expect(sql).not.toContain("s3_secret_access_key")
    // The credential lives only in the clearly-marked fields.
    expect(credentialSql).toBe("SET s3_secret_access_key='minio123';")
    expect(runnableSql).toContain("SET s3_secret_access_key='minio123'")
  })

  it("runnableSql concatenates setup + config + credential + read", () => {
    const { setupSql, configSql, credentialSql, readSql, runnableSql } = duckdbReadParquetSql({ s3: S3_MINIO, key: "k" })
    expect(runnableSql).toContain(setupSql)
    expect(runnableSql).toContain(configSql)
    expect(runnableSql).toContain(credentialSql)
    expect(runnableSql).toContain(readSql)
  })

  it("readSql is a SELECT * FROM read_parquet", () => {
    const { readSql } = duckdbReadParquetSql({ s3: S3_MINIO, key: "datasets/alice/q1.parquet" })
    expect(readSql).toBe("SELECT * FROM read_parquet('s3://my-bucket/datasets/alice/q1.parquet');")
  })

  it("sql concatenates all three parts", () => {
    const { setupSql, configSql, readSql, sql } = duckdbReadParquetSql({ s3: S3_MINIO, key: "k" })
    expect(sql).toContain(setupSql)
    expect(sql).toContain(configSql)
    expect(sql).toContain(readSql)
  })

  it("AWS: https → ssl=true, forcePathStyle=false → vhost", () => {
    const { configSql } = duckdbReadParquetSql({ s3: S3_AWS, key: "k" })
    expect(configSql).toContain("SET s3_url_style='vhost'")
    expect(configSql).toContain("SET s3_use_ssl=true")
  })

  it("AWS: region from options", () => {
    const { configSql } = duckdbReadParquetSql({ s3: S3_AWS, key: "k" })
    expect(configSql).toContain("SET s3_region='eu-west-1'")
  })

  it("glob:true appends /*.parquet to the key", () => {
    const { uri, readSql } = duckdbReadParquetSql({ s3: S3_MINIO, key: "datasets/alice", glob: true })
    expect(uri).toBe("s3://my-bucket/datasets/alice/*.parquet")
    expect(readSql).toContain("*.parquet")
  })

  it("glob:true with trailing slash on key is normalized", () => {
    const { uri } = duckdbReadParquetSql({ s3: S3_MINIO, key: "datasets/alice/", glob: true })
    expect(uri).toBe("s3://my-bucket/datasets/alice/*.parquet")
  })

  it("single quotes in credentials and key are escaped (SQL injection guard)", () => {
    const s3WithQuote = {
      ...S3_MINIO,
      bucket: "my-bucket",
      secretAccessKey: "sec'ret",
      accessKeyId: "aki'd",
    }
    // Check the full runnable script — it is the only field carrying the secret.
    const { runnableSql } = duckdbReadParquetSql({ s3: s3WithQuote, key: "datasets/alice'x/q1.parquet" })
    // escaped forms must appear
    expect(runnableSql).toContain("sec''ret")
    expect(runnableSql).toContain("aki''d")
    expect(runnableSql).toContain("alice''x")
    // raw unescaped single quotes must NOT appear inside any SQL string literal
    // (the outer framework quotes are fine; we check that no lone ' breaks a literal)
    const withoutSetupAndLoad = runnableSql.replace(/INSTALL httpfs;?\nLOAD httpfs;?/, "")
    const singleQuoteMatches = withoutSetupAndLoad.match(/(?<!')'(?!')/g) ?? []
    // Only the wrapping quotes around each SET value and read_parquet should remain:
    // SET k='v'; → 2 quotes per SET statement (6 SET lines = 12) + read_parquet 2 = 14 max.
    // Any extra means an unescaped quote leaked into a value.
    expect(singleQuoteMatches.length).toBeLessThanOrEqual(14)
  })
})

// ---------------------------------------------------------------------------
// Integration: push Parquet bytes, pull back via MemoryObjectStore
// ---------------------------------------------------------------------------

function makeParquetApp(col = createParquetCollection({ name: "datasets", storagePath: "datasets/{owner}/{file}" })) {
  const store = new MemoryObjectStore(new Map())
  const config: SyncConfig = { version: 1, collections: [col] }

  const opts: SyncRouterOptions = {
    store,
    config,
    roleResolver: async (): Promise<AuthResult> => ({
      identity: "user-1",
      roles: ["public", "cap:write:datasets"],
    }),
  }
  return { app: createSyncRouter(opts), store }
}

describe("Parquet push/pull integration (MemoryObjectStore)", () => {
  it("pushes raw Parquet bytes and pulls them back identically", async () => {
    const { app } = makeParquetApp()

    const pushRes = await app.request("/push/datasets/alice/q1.parquet", {
      method: "POST",
      headers: { "Content-Type": PARQUET_MIME_TYPE },
      body: PARQUET_BYTES,
    })
    expect(pushRes.status).toBe(200)
    const { hash } = await pushRes.json()
    expect(typeof hash).toBe("string")
    expect(hash.length).toBe(64) // SHA-256 hex

    const pullRes = await app.request("/pull/datasets/alice/q1.parquet")
    expect(pullRes.status).toBe(200)
    const body = await pullRes.arrayBuffer()
    expect(new Uint8Array(body)).toEqual(new Uint8Array(PARQUET_BYTES))
    expect(pullRes.headers.get("content-type")).toContain(PARQUET_MIME_TYPE)
  })

  it("rejects push with JSON content-type (415)", async () => {
    const { app } = makeParquetApp()

    const res = await app.request("/push/datasets/alice/q1.parquet", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: {} }),
    })
    expect(res.status).toBe(415)
  })

  it("accepts octet-stream content-type (part of PARQUET_MIME_TYPES)", async () => {
    const { app } = makeParquetApp()

    const res = await app.request("/push/datasets/alice/q1.parquet", {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: PARQUET_BYTES,
    })
    expect(res.status).toBe(200)
  })

  it("returns 404 on pull when nothing stored", async () => {
    const { app } = makeParquetApp()
    const res = await app.request("/pull/datasets/alice/missing.parquet")
    expect(res.status).toBe(404)
  })

  it("last-write-wins: second push overwrites first", async () => {
    const { app } = makeParquetApp()

    const bytes1 = Buffer.from("PAR1-v1")
    const bytes2 = Buffer.from("PAR1-v2")

    await app.request("/push/datasets/alice/file.parquet", {
      method: "POST",
      headers: { "Content-Type": PARQUET_MIME_TYPE },
      body: bytes1,
    })
    await app.request("/push/datasets/alice/file.parquet", {
      method: "POST",
      headers: { "Content-Type": PARQUET_MIME_TYPE },
      body: bytes2,
    })

    const pullRes = await app.request("/pull/datasets/alice/file.parquet")
    const body = await pullRes.arrayBuffer()
    expect(new Uint8Array(body)).toEqual(new Uint8Array(bytes2))
  })
})

// ---------------------------------------------------------------------------
// createSealedParquetCollection — config factory
// ---------------------------------------------------------------------------

describe("createSealedParquetCollection", () => {
  it("defaults: authenticated read+write, no rate limit, 256 MB (E2EE preset is not public by default)", () => {
    const col = createSealedParquetCollection({
      name: "enc-datasets",
      storagePath: "enc/{owner}/{objectId}",
    })
    expect(col.name).toBe("enc-datasets")
    // E2EE preset defaults to authenticated read (not public).
    expect(col.readRoles).toEqual(["cap:read:enc-datasets"])
    expect(col.writeRoles).toEqual(["cap:write:enc-datasets"])
    expect(col.encryption).toBe("none")
    expect(col.maxBodyBytes).toBe(256 * 1024 * 1024)
    expect(col.allowedMimeTypes).toEqual(["application/octet-stream"])
    expect(col.rateLimit).toBeNull()
  })

  it("forces allowedMimeTypes to application/octet-stream (NOT Parquet MIME types)", () => {
    const col = createSealedParquetCollection({ name: "x", storagePath: "x/{id}" })
    expect(col.allowedMimeTypes).toEqual(["application/octet-stream"])
    expect(col.allowedMimeTypes).not.toContain("application/vnd.apache.parquet")
  })

  it("forces encryption:'none'", () => {
    const col = createSealedParquetCollection({ name: "x", storagePath: "x/{id}" })
    expect(col.encryption).toBe("none")
  })

  it("read:'public' → readRoles=['public']", () => {
    const col = createSealedParquetCollection({ name: "x", storagePath: "x/{id}", read: "public", write: "authenticated" })
    expect(col.readRoles).toEqual(["public"])
    expect(col.pushOnly).toBeUndefined()
  })

  it("read:'authenticated' → readRoles=['cap:read:x']", () => {
    const col = createSealedParquetCollection({ name: "x", storagePath: "x/{id}", read: "authenticated", write: "public" })
    expect(col.readRoles).toEqual(["cap:read:x"])
  })

  it("read:'none' → pushOnly:true", () => {
    const col = createSealedParquetCollection({ name: "x", storagePath: "x/{id}", read: "none", write: "public" })
    expect(col.pushOnly).toBe(true)
    expect(col.pullOnly).toBeUndefined()
  })

  it("write:'none' → pullOnly:true", () => {
    const col = createSealedParquetCollection({ name: "x", storagePath: "x/{id}", read: "public", write: "none" })
    expect(col.pullOnly).toBe(true)
    expect(col.pushOnly).toBeUndefined()
  })

  it("custom string[] roles are passed verbatim", () => {
    const col = createSealedParquetCollection({
      name: "x",
      storagePath: "x/{id}",
      read: ["space:member"],
      write: ["space:member"],
    })
    expect(col.readRoles).toEqual(["space:member"])
    expect(col.writeRoles).toEqual(["space:member"])
  })

  it("throws when both read and write are 'none'", () => {
    expect(() =>
      createSealedParquetCollection({ name: "x", storagePath: "x/{id}", read: "none", write: "none" }),
    ).toThrowError(/both read and write are "none"/)
  })

  it("auto-enables listable when last storagePath segment is a {param}", () => {
    const col = createSealedParquetCollection({ name: "x", storagePath: "spaces/{spaceId}/enc/{objectId}" })
    expect(col.listable).toBe(true)
  })

  it("does NOT enable listable when last segment is not a {param}", () => {
    const col = createSealedParquetCollection({ name: "x", storagePath: "spaces/{spaceId}/enc/fixed" })
    expect(col.listable).toBeFalsy()
  })

  it("maxBodyBytes override", () => {
    const col = createSealedParquetCollection({ name: "x", storagePath: "x/{id}", maxBodyBytes: 67_108_864 })
    expect(col.maxBodyBytes).toBe(67_108_864)
  })

  it("cacheDurationMs is forwarded", () => {
    const col = createSealedParquetCollection({ name: "x", storagePath: "x/{id}", cacheDurationMs: 60_000 })
    expect(col.cacheDurationMs).toBe(60_000)
  })

  it("resulting config passes validateConfig", () => {
    const col = createSealedParquetCollection({
      name: "private-datasets",
      storagePath: "spaces/{spaceId}/objects/parquet-enc/{objectId}",
      read: ["space:member"],
      write: ["space:member"],
      maxBodyBytes: 67_108_864,
    })
    const config: SyncConfig = { version: 1, collections: [col] }
    const errors = validateConfig(config)
    expect(errors).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// Integration: sealed collection accepts octet-stream bytes
// ---------------------------------------------------------------------------

describe("createSealedParquetCollection push/pull integration", () => {
  it("pushes octet-stream bytes and pulls them back", async () => {
    const col = createSealedParquetCollection({
      name: "enc-datasets",
      storagePath: "enc/{spaceId}/{objectId}",
      read: ["space:member"],
      write: ["space:member"],
    })
    const store = new MemoryObjectStore(new Map())
    const config: SyncConfig = { version: 1, collections: [col] }
    const opts: SyncRouterOptions = {
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({
        identity: "user-1",
        roles: ["space:member"],
      }),
    }
    const app = createSyncRouter(opts)

    // AES-GCM sealed bytes (simulated: just opaque binary)
    const sealedBytes = new Uint8Array([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x01, 0x02])

    const pushRes = await app.request("/push/enc/space-1/obj-1", {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: sealedBytes,
    })
    expect(pushRes.status).toBe(200)

    const pullRes = await app.request("/pull/enc/space-1/obj-1")
    expect(pullRes.status).toBe(200)
    const body = await pullRes.arrayBuffer()
    expect(new Uint8Array(body)).toEqual(sealedBytes)
  })

  it("rejects Parquet MIME type (sealed collection is octet-stream only)", async () => {
    const col = createSealedParquetCollection({
      name: "enc-datasets",
      storagePath: "enc/{spaceId}/{objectId}",
    })
    const store = new MemoryObjectStore(new Map())
    const config: SyncConfig = { version: 1, collections: [col] }
    const opts: SyncRouterOptions = {
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({
        identity: "user-1",
        roles: ["public", "cap:write:enc-datasets"],
      }),
    }
    const app = createSyncRouter(opts)

    const res = await app.request("/push/enc/space-1/obj-1", {
      method: "POST",
      headers: { "Content-Type": PARQUET_MIME_TYPE },
      body: PARQUET_BYTES,
    })
    expect(res.status).toBe(415)
  })
})
