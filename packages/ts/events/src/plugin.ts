/**
 * Starfish server plugin: intercepts JSON event-batch pushes and encodes them
 * as Parquet files written directly to the object store (typically S3).
 *
 * ## How it works
 *
 * 1. Register a JSON-typed collection (allowedMimeTypes: ["application/json"])
 *    with public write access.
 * 2. Attach this plugin to the sync router.
 * 3. Each push to that collection is intercepted here; the JSON event batch is
 *    encoded as Parquet and stored via `store.putBytes`, short-circuiting the
 *    default JSON document write so no JSON is persisted alongside the Parquet.
 *
 * ## Collection requirement
 *
 * The intercepted collection **must** be JSON-typed — `interceptPush` only
 * receives a populated `rawBody` for JSON collections. A binary (parquet-typed)
 * collection would yield an empty body.
 *
 * ## One file per batch
 *
 * Parquet's column-footer format makes in-place append impractical. Each
 * `send()` call from the SunGlasses adapter writes a unique path (batchId in
 * the storagePath template). DuckDB's `read_parquet('s3://…/**‌/*.parquet')`
 * glob treats all files under the prefix as one logical dataset.
 *
 * ## Batch id
 *
 * The plugin — not the client — assigns the final `{batchId}` path segment: a
 * server-clock-derived, lexicographically-sortable id (see `sortable-id.ts`).
 * The client's URL still carries a `{batchId}` placeholder value, but it's
 * discarded. This makes the `/list` route's ascending key order double as a
 * chronological cursor, which a client-minted id can't guarantee — batches
 * come from many end-user devices with untrusted, possibly-skewed clocks.
 *
 * ## Privacy
 *
 * Never log `distinct_id`, `properties`, or `context`. Log counts only.
 * These values ride as opaque strings into Parquet.
 */

import type {
  ServerPlugin,
  PullHookContext,
  PullInterceptResult,
  PushHookContext,
  PushHookResult,
} from "@drakkar.software/starfish-protocol"
import { getCrypto, bytesToHex, PARQUET_MIME_TYPE } from "@drakkar.software/starfish-protocol"
import type { ObjectStore } from "@drakkar.software/starfish-server"
import { resolveDocumentKey } from "@drakkar.software/starfish-server"
import { encodeParquet } from "./encode.js"
import { generateSortableBatchId } from "./sortable-id.js"

/** Options for {@link createEventsServerPlugin}. */
export interface EventsPluginOptions {
  /**
   * Object store the plugin writes Parquet files to.
   * Must implement `putBytes` (e.g. `S3ObjectStore` from `starfish-server/s3`).
   * Pass the **same** store instance that you pass to `createSyncRouter`.
   */
  store: ObjectStore

  /**
   * Name of the collection to intercept.
   * Must match the `name` field in the `SyncConfig.collections` entry.
   * Example: `"events"`
   */
  collection: string

  /**
   * Storage-path template for the output Parquet key.
   * Supports `{param}` placeholders resolved from the push URL's path params,
   * except the **last** segment, which must be a `{param}` too but is always
   * overridden with a server-assigned sortable batch id (see "Batch id" above)
   * rather than the client-supplied value.
   * Example: `"events/{app}/{batchId}"` → `"events/myapp/<server-assigned-id>"`
   *
   * The plugin appends `.parquet` when the resolved key doesn't already end
   * with it, so you can omit the extension from the template.
   */
  storagePath: string
}

/**
 * Create a Starfish server plugin that encodes SunGlasses event batches as
 * Parquet and writes them to the object store.
 *
 * @example
 * ```ts
 * import { S3ObjectStore } from "@drakkar.software/starfish-server/s3"
 * import { createEventsServerPlugin } from "@drakkar.software/starfish-events"
 *
 * const store = new S3ObjectStore({ bucket: "my-bucket", ... })
 * const eventsPlugin = createEventsServerPlugin({
 *   store,
 *   collection: "events",
 *   storagePath: "events/{app}/{batchId}",
 * })
 *
 * const sync = createSyncRouter({
 *   store,
 *   config: {
 *     version: 1,
 *     collections: [{
 *       name: "events",
 *       storagePath: "events/{app}/{batchId}",
 *       readRoles: ["public"],
 *       writeRoles: ["public"],
 *       encryption: "none",
 *       allowedMimeTypes: ["application/json"],  // ← JSON-typed, not parquet
 *       maxBodyBytes: 8_000_000,
 *     }],
 *   },
 *   plugins: [eventsPlugin],
 * })
 * ```
 */
export function createEventsServerPlugin(opts: EventsPluginOptions): ServerPlugin {
  const { store, collection, storagePath } = opts

  if (!store.putBytes) {
    throw new Error(
      "[starfish-events] the provided ObjectStore does not implement putBytes. " +
        "Use S3ObjectStore or another store that supports binary writes.",
    )
  }

  // The last storagePath segment names the batch-id param (e.g. "{batchId}" in
  // "events/{app}/{batchId}"). Resolved once at construction so a misconfigured
  // template fails fast at startup rather than on the first push.
  const batchIdParam = lastPathParamName(storagePath)

  return {
    name: "starfish-events",

    interceptPush: async (ctx: PushHookContext): Promise<PushHookResult> => {
      // Only intercept the configured collection; let everything else proceed.
      if (ctx.collection !== collection) return { action: "proceed" }

      // Parse the client push envelope: { data: { events: [...] }, baseHash }
      let events: Record<string, unknown>[]
      try {
        const envelope = JSON.parse(ctx.rawBody) as {
          data?: { events?: unknown[] }
          baseHash?: string | null
        }
        const raw = envelope?.data?.events
        events = Array.isArray(raw) ? (raw as Record<string, unknown>[]) : []
      } catch {
        return {
          action: "reject",
          status: 400,
          error: "Invalid JSON body — expected { data: { events: [...] }, baseHash }",
        }
      }

      // Stamp ingest time server-side (never log events contents). The batch id
      // below is minted from this same instant, so the filename and
      // `received_at` agree.
      const now = Date.now()
      const receivedAt = new Date(now).toISOString()
      const rows = events.map((e) => ({ ...e, received_at: receivedAt }))

      // Encode to Parquet.
      let parquetBytes: Uint8Array
      try {
        parquetBytes = encodeParquet(rows)
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err)
        console.error(`[starfish-events] Parquet encoding failed: ${msg}`)
        return { action: "reject", status: 500, error: "Parquet encoding failed" }
      }

      // Resolve the output key from the storagePath template + URL params, but
      // override the batch-id param with a server-assigned, lexicographically-
      // sortable id — never the client-supplied one. Batches arrive from many
      // end-user devices with untrusted clocks, so only a single server clock
      // can make the /list route's ascending key order a correct chronological
      // cursor.
      const serverBatchId = generateSortableBatchId(now)
      let key = resolveDocumentKey(storagePath, { ...ctx.params, [batchIdParam]: serverBatchId })
      if (!key.endsWith(".parquet")) key += ".parquet"

      // Write to the object store. Failure propagates as 500 so the client
      // retries (SunGlasses adapter throws on non-2xx → SDK requeues the batch).
      await store.putBytes!(key, parquetBytes, { contentType: PARQUET_MIME_TYPE })

      // Compute SHA-256 of the stored bytes to match the binary push response format.
      const cr = getCrypto()
      // Cast: hyparquet-writer always returns a plain ArrayBuffer (never SharedArrayBuffer).
      const hashBuf = await cr.subtle.digest("SHA-256", parquetBytes.buffer as ArrayBuffer)
      const hash = bytesToHex(new Uint8Array(hashBuf))

      // Privacy: log only counts, never event contents.
      console.log(
        `[starfish-events] wrote ${events.length} event(s) → ${key} (${parquetBytes.byteLength} bytes)`,
      )

      return { action: "respond", status: 200, body: { hash } }
    },

    interceptPull: async (ctx: PullHookContext): Promise<PullInterceptResult> => {
      // Only handle the configured collection.
      if (ctx.collection !== collection) return { action: "proceed" }

      if (!store.getBytes) return { action: "proceed" }

      // Resolve the same key the push hook wrote (storagePath template + params + .parquet).
      let key = resolveDocumentKey(storagePath, ctx.params)
      if (!key.endsWith(".parquet")) key += ".parquet"

      const result = await store.getBytes(key)
      if (result == null) return { action: "proceed" }

      return { action: "respond", status: 200, body: result.body, contentType: result.contentType }
    },
  }
}

/** Extract the `{param}` name from the last `storagePath` segment (e.g. "batchId" from "{batchId}"). */
function lastPathParamName(storagePath: string): string {
  const lastSegment = storagePath.split("/").pop() ?? ""
  const match = /^\{([^}]+)\}$/.exec(lastSegment)
  if (!match) {
    throw new Error(
      `[starfish-events] storagePath "${storagePath}" must end with a {param} segment ` +
        '(e.g. "events/{app}/{batchId}")',
    )
  }
  return match[1]!
}
