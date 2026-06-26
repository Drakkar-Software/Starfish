/**
 * Parquet / DuckDB collection helpers.
 *
 * A **Parquet collection** is a binary collection (no `application/json` in
 * `allowedMimeTypes`) whose bytes are Apache Parquet files generated
 * client-side, pushed to the server, stored verbatim on S3, and queried
 * directly by DuckDB via the `httpfs` extension — without any server
 * round-trip for reads.
 *
 * All transport, auth, rate limiting, and S3 storage is provided by the
 * existing binary-collection machinery. This module adds:
 *
 * - {@link createParquetCollection} — builds a `CollectionConfig` preset with
 *   configurable read/write auth and rate limiting.
 * - {@link duckdbReadParquetSql} — generates DuckDB SQL to query the stored
 *   Parquet files via `s3://`.
 *
 * @example
 * ```ts
 * import { createParquetCollection, duckdbReadParquetSql, resolveDocumentKey } from "@drakkar.software/starfish-server"
 *
 * const col = createParquetCollection({
 *   name: "datasets",
 *   storagePath: "datasets/{owner}/{dataset}",
 *   read: "public",        // DuckDB reads S3 directly — no auth on reads
 *   write: "authenticated",
 * })
 *
 * const s3Opts = { endpoint: "http://localhost:9000", bucket: "starfish", accessKeyId: "...", secretAccessKey: "..." }
 * const key = resolveDocumentKey("datasets/{owner}/{dataset}", { owner: "alice", dataset: "sales.parquet" })
 * const { sql } = duckdbReadParquetSql({ s3: s3Opts, key })
 * // → Run `sql` in DuckDB to query the file
 * ```
 */

import type { CollectionConfig, CollectionRateLimitConfig } from "./config/schema.js"
import type { S3StorageOptions } from "./storage/s3.js"
import { ROLE_PUBLIC } from "./constants.js"
import { PARQUET_MIME_TYPES, PARQUET_MIME_TYPE } from "@drakkar.software/starfish-protocol"

// Re-export so callers have a single import surface for the Parquet feature.
export { PARQUET_MIME_TYPE, PARQUET_MIME_TYPES }
export { resolveDocumentKey } from "./router/route-builder.js"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Controls who may read or write a parquet collection.
 *
 * - `"public"` — no authentication required (`ROLE_PUBLIC`).
 * - `"authenticated"` — requires a valid cap-cert scoped to this collection
 *   (`cap:read:<name>` / `cap:write:<name>`).
 * - `"none"` — the corresponding endpoint (pull or push) is **disabled**.
 * - `string[]` — custom role list, passed verbatim.
 */
export type ParquetAccessMode = "public" | "authenticated" | "none" | string[]

export interface ParquetCollectionOptions {
  /** Unique collection name. Drives cap-cert role names when mode is `"authenticated"`. */
  name: string
  /**
   * Storage key template with `{param}` placeholders
   * (e.g. `"datasets/{owner}/{dataset}"`).
   *
   * Each resolved placeholder becomes part of the S3 object key.  When the
   * **last segment** is a `{param}`, `listable` is auto-enabled so DuckDB
   * can glob all files under a prefix with `read_parquet('s3://…/*.parquet')`.
   */
  storagePath: string
  /**
   * Who may **pull** from this collection.
   *
   * DuckDB queries S3 directly — the server is bypassed for reads — so
   * `"public"` is the most common setting for analytics data.
   *
   * @default `"public"`
   */
  read?: ParquetAccessMode
  /**
   * Who may **push** to this collection (i.e. ingest Parquet files).
   *
   * @default `"authenticated"`
   */
  write?: ParquetAccessMode
  /**
   * Rate-limiting for this collection.
   *
   * - `"none"` (default) — no rate limit on any action.
   * - A {@link CollectionRateLimitConfig} object — forwarded verbatim; supports
   *   per-action (`push` / `pull` / `list`) and per-identity / per-ip limits.
   *
   * @default `"none"`
   */
  rateLimit?: "none" | CollectionRateLimitConfig
  /**
   * Maximum push body size in bytes.
   * @default 268435456 (256 MiB)
   */
  maxBodyBytes?: number
  /** `Cache-Control: max-age` duration (ms) added to pull responses. */
  cacheDurationMs?: number
}

// ---------------------------------------------------------------------------
// createParquetCollection
// ---------------------------------------------------------------------------

/**
 * Builds a {@link CollectionConfig} preset ready for Apache Parquet / DuckDB
 * workflows.
 *
 * The resulting collection:
 * - Accepts all common Parquet MIME types (`allowedMimeTypes = PARQUET_MIME_TYPES`).
 * - Forces `encryption: "none"` — client-side delegated encryption would
 *   store ciphertext on S3, which DuckDB cannot read.
 * - Enables `listable` automatically when the last `storagePath` segment is a
 *   `{param}`, so DuckDB can discover and glob all files under a prefix.
 * - Maps `read` / `write` to the correct role arrays and `pushOnly` / `pullOnly`
 *   flags; supports `"public"`, `"authenticated"`, `"none"`, or custom roles.
 *
 * @throws {Error} if both `read` and `write` are `"none"`.
 *
 * @example
 * ```ts
 * createParquetCollection({
 *   name: "sales",
 *   storagePath: "analytics/{owner}/{report}",
 *   read: "public",         // anyone can read (DuckDB hits S3 directly)
 *   write: "authenticated", // only cap-cert holders may push
 * })
 * ```
 */
export function createParquetCollection(opts: ParquetCollectionOptions): CollectionConfig {
  const {
    name,
    storagePath,
    read = "public",
    write = "authenticated",
    rateLimit = "none",
    maxBodyBytes = 256 * 1024 * 1024,
    cacheDurationMs,
  } = opts

  if (read === "none" && write === "none") {
    throw new Error(
      `createParquetCollection("${name}"): both read and write are "none" — ` +
        "the collection would be completely inaccessible. " +
        'Set at least one to "public", "authenticated", or a custom role array.',
    )
  }

  const readRoles = resolveAccessRoles(name, read, "read")
  const writeRoles = resolveAccessRoles(name, write, "write")

  // When the endpoint is disabled, we still need a syntactically valid role
  // list because the config validator checks that readRoles / writeRoles are
  // non-empty when the corresponding endpoint is active. With pushOnly=true
  // the pull route is removed, so readRoles is never checked at runtime.
  const pushOnly = read === "none" ? true : undefined
  const pullOnly = write === "none" ? true : undefined

  // Auto-enable listable when the last storagePath segment is a {param}.
  // This lets DuckDB glob all objects under the prefix via read_parquet('s3://…/*.parquet').
  const listable = isLastSegmentParam(storagePath) || undefined

  return {
    name,
    storagePath,
    readRoles,
    writeRoles,
    // Force "none": delegated encryption stores ciphertext — DuckDB cannot decode it.
    encryption: "none",
    maxBodyBytes,
    allowedMimeTypes: [...PARQUET_MIME_TYPES],
    listable,
    // Explicit null disables rate limiting even when a global rateLimit is configured.
    rateLimit: rateLimit === "none" ? null : rateLimit,
    ...(cacheDurationMs != null && { cacheDurationMs }),
    ...(pushOnly && { pushOnly }),
    ...(pullOnly && { pullOnly }),
  }
}

// ---------------------------------------------------------------------------
// createSealedParquetCollection
// ---------------------------------------------------------------------------

/**
 * Options for {@link createSealedParquetCollection}.
 *
 * Identical shape to {@link ParquetCollectionOptions} — the same read/write
 * role modes, rate-limiting, max size, and cache-duration knobs apply.
 */
export type SealedParquetCollectionOptions = ParquetCollectionOptions

/**
 * Builds a {@link CollectionConfig} preset for **client-sealed** Parquet
 * datasets (E2EE / end-to-end encrypted).
 *
 * Use this when you want the server to store opaque ciphertext rather than
 * readable Parquet bytes. The client AES-256-GCM-seals the Parquet file under
 * the space keyring CEK (AAD bound to the storage path) before uploading, and
 * unseals it after downloading. The server and S3 bucket never see plaintext.
 *
 * **Trade-off:** because the stored bytes are ciphertext, they are **not**
 * valid Parquet files — DuckDB cannot read them via `read_parquet('s3://…')`.
 * Use {@link createParquetCollection} instead when server-side / S3-direct
 * DuckDB querying is the goal; use this variant when the priority is E2EE and
 * clients query locally (e.g. DuckDB-WASM after unsealing).
 *
 * Compared to {@link createParquetCollection}, the differences are:
 * - `read` defaults to `"authenticated"` (not `"public"`) — E2EE data should
 *   not be world-downloadable by default.
 * - `allowedMimeTypes: ["application/octet-stream"]` — the sealed bytes are
 *   opaque binary, not Parquet MIME typed.
 *
 * @throws {Error} if both `read` and `write` are `"none"`.
 *
 * @example
 * ```ts
 * createSealedParquetCollection({
 *   name: "private-datasets",
 *   storagePath: "spaces/{spaceId}/objects/parquet-enc/{objectId}",
 *   read: ["space:member"],
 *   write: ["space:member"],
 *   maxBodyBytes: 67_108_864,
 * })
 * ```
 */
export function createSealedParquetCollection(opts: SealedParquetCollectionOptions): CollectionConfig {
  const { name, read = "authenticated", write = "authenticated" } = opts

  if (read === "none" && write === "none") {
    throw new Error(
      `createSealedParquetCollection("${name}"): both read and write are "none" — ` +
        "the collection would be completely inaccessible. " +
        'Set at least one to "public", "authenticated", or a custom role array.',
    )
  }

  return {
    // Build the full config via createParquetCollection (same logic, same fields),
    // then override only the MIME allowlist — sealed bytes are opaque binary.
    ...createParquetCollection({ ...opts, read, write }),
    allowedMimeTypes: ["application/octet-stream"],
  }
}

// ---------------------------------------------------------------------------
// duckdbReadParquetSql
// ---------------------------------------------------------------------------

export interface DuckdbParquetSqlOptions {
  /** S3 options — same object passed to `S3ObjectStore`. */
  s3: S3StorageOptions
  /**
   * Resolved S3 object key.
   *
   * Use {@link resolveDocumentKey} from this package to derive the key from
   * `storagePath` and its `{param}` values.
   *
   * For a **glob** over a listable prefix, pass the prefix string (without
   * trailing slash) and set `glob: true`.
   */
  key: string
  /**
   * When `true`, appends `&#47;*.parquet` to `key`, producing a glob that reads
   * all Parquet objects under the prefix.  Use with `listable` collections
   * where the last path segment is the per-file parameter.
   *
   * @default false
   */
  glob?: boolean
}

export interface DuckdbParquetSqlResult {
  /** Full `s3://…` URI passed to `read_parquet()`. */
  uri: string
  /** `INSTALL httpfs;\nLOAD httpfs;` — run once per DuckDB session. */
  setupSql: string
  /** `SET s3_*` configuration statements. */
  configSql: string
  /** `SELECT * FROM read_parquet('…')` statement. */
  readSql: string
  /** All statements concatenated into one runnable script. */
  sql: string
}

/**
 * Generates DuckDB SQL to query a Parquet file (or prefix glob) stored on S3
 * by a Parquet collection.
 *
 * No DuckDB package is required — execute the returned `sql` yourself:
 * via the DuckDB CLI, the Node.js `duckdb` package, DuckDB-WASM, etc.
 *
 * @example
 * ```ts
 * import { duckdbReadParquetSql, resolveDocumentKey } from "@drakkar.software/starfish-server"
 *
 * const s3 = { endpoint: "http://localhost:9000", bucket: "data", accessKeyId: "minio", secretAccessKey: "minio123" }
 * const key = resolveDocumentKey("analytics/{owner}/{report}", { owner: "alice", report: "q1.parquet" })
 * const { sql } = duckdbReadParquetSql({ s3, key })
 *
 * // For all reports by alice:
 * const prefix = resolveDocumentKey("analytics/{owner}", { owner: "alice" })
 * const { sql: globSql } = duckdbReadParquetSql({ s3, key: prefix, glob: true })
 * // → SELECT * FROM read_parquet('s3://data/analytics/alice/*.parquet')
 * ```
 */
export function duckdbReadParquetSql(opts: DuckdbParquetSqlOptions): DuckdbParquetSqlResult {
  const { s3, key, glob = false } = opts

  const url = new URL(s3.endpoint)
  const useSsl = url.protocol === "https:"
  // `host` includes port when non-standard (e.g. "localhost:9000").
  const host = url.host
  // forcePathStyle defaults to true (MinIO/self-hosted); AWS virtual-hosted style when false.
  const pathStyle = s3.forcePathStyle ?? true
  const urlStyle = pathStyle ? "path" : "vhost"

  const sq = (v: string) => v.replaceAll("'", "''")

  const normalizedKey = key.replace(/\/\*\.parquet$/, "").replace(/\/*$/, "")
  const resolvedKey = glob
    ? (normalizedKey ? normalizedKey + "/*.parquet" : "*.parquet")
    : key
  const uri = `s3://${sq(s3.bucket)}/${sq(resolvedKey)}`

  const setupSql = "INSTALL httpfs;\nLOAD httpfs;"
  const configLines = [
    `SET s3_endpoint='${sq(host)}';`,
    `SET s3_access_key_id='${sq(s3.accessKeyId)}';`,
    `SET s3_secret_access_key='${sq(s3.secretAccessKey)}';`,
    `SET s3_region='${sq(s3.region ?? "us-east-1")}';`,
    `SET s3_url_style='${urlStyle}';`,
    `SET s3_use_ssl=${useSsl};`,
  ]
  const configSql = configLines.join("\n")

  const readSql = `SELECT * FROM read_parquet('${uri}');`

  const sql = [setupSql, configSql, readSql].join("\n")

  return { uri, setupSql, configSql, readSql, sql }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function resolveAccessRoles(name: string, mode: ParquetAccessMode, op: "read" | "write"): string[] {
  if (mode === "public") return [ROLE_PUBLIC]
  if (mode === "authenticated") return [`cap:${op}:${name}`]
  if (mode === "none") {
    // Provide a placeholder role that is never actually checked — the
    // corresponding endpoint is disabled via pushOnly / pullOnly.
    return [`cap:${op}:${name}`]
  }
  // Custom string[] — verbatim pass-through.
  return mode as string[]
}

/** Returns true when the last non-empty storagePath segment is a `{param}`. */
function isLastSegmentParam(storagePath: string): boolean {
  const lastSegment = storagePath.replace(/\/+$/, "").split("/").pop() ?? ""
  return /^\{[^}]+\}$/.test(lastSegment)
}
