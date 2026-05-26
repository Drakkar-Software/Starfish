import { UNSAFE_KEYS } from "@drakkar.software/starfish-protocol"
import type { ObjectStore, StoreContext } from "../storage/base.js"
import { pull } from "../protocol/pull.js"
import { push, appendSegPrefix, appendChunkKey, type Author } from "../protocol/push.js"
import type { PushSuccess, StoredDocument, AppendElement } from "../protocol/types.js"
import { ERROR_HASH_MISMATCH } from "../constants.js"

const SAFE_PARAM = /^[a-zA-Z0-9._:@-]+$/
const UNSAFE_KEY = /\.\.|[\x00-\x1f]|\/\//

export function validateUrlNotPrivate(url: string): boolean {
  try {
    const parsed = new URL(url)
    const hostname = parsed.hostname
    if (!hostname) return false

    // Exact loopback/local matches
    const blocked = ["localhost", "127.0.0.1", "::1", "::", "0.0.0.0"]
    if (blocked.includes(hostname)) return false

    // Strip IPv6 brackets for analysis
    const bare = hostname.startsWith("[") ? hostname.slice(1, -1) : hostname

    // IPv6 private/loopback/link-local checks
    const lower = bare.toLowerCase()
    if (lower === "::1" || lower === "::") return false
    if (lower.startsWith("fc") || lower.startsWith("fd")) return false  // fc00::/7 unique-local
    if (/^fe[89ab][0-9a-f]/i.test(lower)) return false  // fe80::/10 link-local (fe80:: - febf::)
    // IPv4-mapped IPv6 (::ffff:x.x.x.x)
    const v4mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
    if (v4mapped) {
      return isPublicIPv4(v4mapped[1]!)
    }
    // IPv4-mapped IPv6 in compressed hex form (e.g. `::ffff:7f00:1`). `new URL`
    // normalises `::ffff:127.0.0.1` to this, so the dotted-quad branch above
    // misses it — without this, `http://[::ffff:127.0.0.1]/` (loopback) passes.
    const v4mappedHex = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/)
    if (v4mappedHex) {
      const hi = parseInt(v4mappedHex[1]!, 16)
      const lo = parseInt(v4mappedHex[2]!, 16)
      return isPublicIPv4(`${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`)
    }

    // IPv4 checks
    const parts = bare.split(".")
    if (parts.length === 4 && parts.every((p) => /^\d+$/.test(p))) {
      return isPublicIPv4(bare)
    }

    return true
  } catch {
    return false
  }
}

function isPublicIPv4(ip: string): boolean {
  const parts = ip.split(".")
  if (parts.length !== 4) return false
  const first = parseInt(parts[0]!, 10)
  const second = parseInt(parts[1]!, 10)
  if (first === 0) return false                                // 0.0.0.0/8
  if (first === 10) return false                               // 10.0.0.0/8
  if (first === 127) return false                              // 127.0.0.0/8
  if (first === 169 && second === 254) return false            // 169.254.0.0/16 link-local
  if (first === 172 && second >= 16 && second <= 31) return false  // 172.16.0.0/12
  if (first === 192 && second === 168) return false            // 192.168.0.0/16
  return true
}

export function validatePathSegment(value: string): boolean {
  return SAFE_PARAM.test(value)
}

/**
 * True when a resolved storage key contains a path-traversal or injection
 * sequence (`..`, control chars, or `//`). The single guard every read/write
 * path must apply to its resolved `documentKey` before touching the store —
 * `validatePathSegment` only constrains a single param's charset (it admits
 * `..`), so this is what actually blocks traversal in the composed key.
 */
export function isUnsafeDocumentKey(documentKey: string): boolean {
  return UNSAFE_KEY.test(documentKey)
}

export function deepSanitize(obj: Record<string, unknown>): Record<string, unknown> {
  const safe: Record<string, unknown> = {}
  for (const [key, val] of Object.entries(obj)) {
    if (UNSAFE_KEYS.has(key)) continue
    if (val != null && typeof val === "object" && !Array.isArray(val)) {
      safe[key] = deepSanitize(val as Record<string, unknown>)
    } else {
      safe[key] = val
    }
  }
  return safe
}

/**
 * Reject documents nested deeper than this. V8's `JSON.parse` is iterative (it does
 * not overflow on deep input), but the recursive `deepSanitize` would blow the call
 * stack with a `RangeError` → a tiny payload becomes an unhandled crash. Real
 * Starfish documents are shallow (a keyring with epochs is ~5 deep), so 64 is far
 * above any legitimate use. Mirrors `MAX_DOC_DEPTH` in the Python server.
 */
export const MAX_DOC_DEPTH = 64

/**
 * Returns `true` iff `obj`'s nesting depth is within `limit`. Walks objects and
 * arrays iteratively (an explicit stack, never the call stack) so the check itself
 * cannot overflow. The push path runs this on the parsed body and rejects anything
 * deeper than `limit` with HTTP 400 before the recursive `deepSanitize` runs.
 */
export function jsonDepthWithin(obj: unknown, limit: number = MAX_DOC_DEPTH): boolean {
  const stack: Array<[unknown, number]> = [[obj, 1]]
  while (stack.length > 0) {
    const [node, depth] = stack.pop()!
    if (depth > limit) return false
    if (node != null && typeof node === "object") {
      const children = Array.isArray(node) ? node : Object.values(node as Record<string, unknown>)
      for (const child of children) {
        if (child != null && typeof child === "object") stack.push([child, depth + 1])
      }
    }
  }
  return true
}

export interface PullResponse {
  body: Record<string, unknown>
  status: number
  headers?: Record<string, string>
}

/**
 * Returns true when the `?withKeyring=` query value should activate the
 * sibling-keyring fetch. Accepts `"1"` or `"true"` (case-insensitive); any
 * other value (including missing) is treated as off.
 */
export function isWithKeyringEnabled(raw: string | null | undefined): boolean {
  if (raw == null) return false
  const v = raw.toLowerCase()
  return v === "1" || v === "true"
}

export async function handleSyncPull(
  documentKey: string,
  store: ObjectStore,
  cacheDurationMs?: number,
  isPublic: boolean = true,
  context?: StoreContext,
  withKeyring: boolean = false,
): Promise<PullResponse> {
  if (isUnsafeDocumentKey(documentKey)) {
    return { body: { error: "Invalid path parameter" }, status: 400 }
  }

  // Regular collections always return the full document. `?checkpoint=` is
  // ignored here (incremental sync is an appendOnly-only feature now); a stale
  // checkpoint param from an older client is harmless.
  const result = await pull(store, documentKey, context)
  const body: Record<string, unknown> = {
    data: result.data,
    hash: result.hash,
    timestamp: result.timestamp,
  }
  if (result.authorPubkey) body["authorPubkey"] = result.authorPubkey
  if (result.authorSignature) body["authorSignature"] = result.authorSignature

  // ?withKeyring=1 optimization: piggyback the collection's sibling keyring
  // doc at `<documentKey>/_keyring` onto the pull response, saving a round-
  // trip on cold start. The keyring projection drops author fields — the
  // keyring document is unsigned in this model.
  //
  // NOTE: the sibling keyring read is authorized by the route layer, not here.
  // The pull handler only sets `withKeyring=true` after checking
  // `<documentKey>/_keyring` against the caller's cap scope, so a cap that
  // denies the keyring (e.g. `scopes.writer(col)`) never reaches this read.
  // This function just performs the storage read.
  if (withKeyring) {
    const keyringKey = `${documentKey}/_keyring`
    // Treat ANY store error as "no keyring" (e.g. a store throwing when the data
    // path is a leaf file and the app keeps its keyring in a separate namespace).
    // The optimization must degrade gracefully, never crash the pull (HTTP 500).
    let keyringRaw: string | null = null
    try {
      keyringRaw = await store.getString(keyringKey, context)
    } catch (e) {
      console.warn(`[Starfish] withKeyring read failed for "${keyringKey}":`, e)
      keyringRaw = null
    }
    if (!keyringRaw) {
      body["keyring"] = null
    } else {
      try {
        const parsed = JSON.parse(keyringRaw) as StoredDocument
        body["keyring"] = {
          data: parsed.data,
          hash: parsed.hash,
          timestamp: result.timestamp,
        }
      } catch (e) {
        console.error(`[Starfish] Corrupt keyring document at key "${keyringKey}":`, e)
        body["keyring"] = null
      }
    }
  }

  let headers: Record<string, string> | undefined
  if (cacheDurationMs != null) {
    const maxAge = Math.floor(cacheDurationMs / 1000)
    const directive = isPublic ? `max-age=${maxAge}` : `private, max-age=${maxAge}`
    headers = { "Cache-Control": directive }
  }

  return { body, status: 200, headers }
}

/**
 * Read only the chunks a segmented (`chunkSize`) append-only pull needs.
 *
 * Each chunk key encodes its first element's `ts`, so the lexicographically sorted
 * key list (one `listKeys` call — no chunk contents) tells us every chunk's ts range:
 *  - `?checkpoint=` → skip every chunk whose whole range is at/below the checkpoint;
 *    only the boundary chunk (the last whose firstTs ≤ checkpoint) and the chunks
 *    after it are read.
 *  - `?last=K` → read only the final ⌈K/chunkSize⌉+1 chunks.
 * Returns the gathered `{ts,data}` envelopes in order; the caller's checkpoint/last
 * filtering then trims precisely (e.g. the ≤checkpoint head of the boundary chunk).
 */
async function readAppendChunks(
  store: ObjectStore,
  documentKey: string,
  checkpoint: number,
  last: number | null,
  chunkSize: number,
  context?: StoreContext,
): Promise<AppendElement[]> {
  if (last === 0) return []
  const chunkKeys = await store.listKeys(appendSegPrefix(documentKey), undefined, context)
  if (chunkKeys.length === 0) return []

  let startIdx = 0
  if (checkpoint > 0) {
    // Boundary = last chunk key ≤ the (same-width) key for the checkpoint ts.
    const cpKey = appendChunkKey(documentKey, checkpoint)
    let lo = 0,
      hi = chunkKeys.length
    while (lo < hi) {
      const mid = (lo + hi) >>> 1
      if (chunkKeys[mid]! <= cpKey) lo = mid + 1
      else hi = mid
    }
    startIdx = Math.max(0, lo - 1) // include the boundary chunk (may hold both ≤ and > checkpoint)
  }

  let neededKeys = chunkKeys.slice(startIdx)
  if (last != null && last > 0 && chunkSize > 0) {
    const maxChunks = Math.ceil(last / chunkSize) + 1
    if (neededKeys.length > maxChunks) neededKeys = neededKeys.slice(-maxChunks)
  }

  const raws = await Promise.all(neededKeys.map((k) => store.getString(k, context)))
  const items: AppendElement[] = []
  for (const raw of raws) {
    if (!raw) continue
    try {
      const arr = JSON.parse(raw) as AppendElement[]
      if (Array.isArray(arr)) for (const el of arr) items.push(el)
    } catch (e) {
      console.error(`[Starfish] Corrupt append-only chunk under "${documentKey}":`, e)
    }
  }
  return items
}

/**
 * Pull handler for appendOnly persist=true collections.
 *
 * Each stored element is a `{ts, data}` envelope. When a checkpoint is requested,
 * returns only elements whose `ts` is strictly greater than the checkpoint, found
 * by binary search (the array is strictly increasing in `ts`). `?last=K` then
 * trims to the last K of those. The full `{ts, data}` envelopes are returned —
 * `data` is plaintext under "none" and an encryptor wrapper under "delegated".
 */
export async function handleAppendOnlyPull(
  documentKey: string,
  store: ObjectStore,
  checkpointParam: string | null | undefined,
  appendField: string,
  cacheDurationMs?: number,
  isPublic: boolean = true,
  lastParam?: string | null,
  context?: StoreContext,
): Promise<PullResponse> {
  if (isUnsafeDocumentKey(documentKey)) {
    return { body: { error: "Invalid path parameter" }, status: 400 }
  }

  let checkpoint = 0
  if (checkpointParam != null) {
    const parsed = parseInt(checkpointParam, 10)
    if (isNaN(parsed) || parsed < 0 || String(parsed) !== checkpointParam) {
      return { body: { error: "Invalid checkpoint" }, status: 400 }
    }
    checkpoint = parsed
  }

  let last: number | null = null
  if (lastParam != null) {
    const parsed = parseInt(lastParam, 10)
    if (isNaN(parsed) || parsed < 0 || String(parsed) !== lastParam) {
      return { body: { error: "Invalid last" }, status: 400 }
    }
    last = parsed
  }

  const now = Date.now()
  const raw = await store.getString(documentKey, context)

  if (!raw) {
    return { body: { data: { [appendField]: [] }, hash: "", timestamp: now }, status: 200 }
  }

  let stored: StoredDocument
  try {
    stored = JSON.parse(raw) as StoredDocument
  } catch (e) {
    console.error(`[Starfish] Corrupt stored document at key "${documentKey}":`, e)
    return { body: { data: { [appendField]: [] }, hash: "", timestamp: now }, status: 200 }
  }

  const storedData = (stored.data as Record<string, unknown>) ?? {}
  const storedHash = stored.hash ?? ""
  // Segmented (`seg`) docs keep the array in sibling chunk objects; read only the
  // chunks the checkpoint/last needs. Legacy single-docs keep the array inline.
  const allItems: AppendElement[] = (stored as { seg?: unknown }).seg === true
    ? await readAppendChunks(store, documentKey, checkpoint, last, (stored as { chunkSize?: number }).chunkSize ?? 0, context)
    : Array.isArray(storedData[appendField])
      ? (storedData[appendField] as AppendElement[])
      : []

  let filteredItems: AppendElement[]
  if (checkpoint > 0) {
    // Elements are strictly increasing in `ts` — binary search for the first
    // index whose ts > checkpoint, then return that suffix.
    let lo = 0, hi = allItems.length
    while (lo < hi) {
      const mid = (lo + hi) >>> 1
      if ((allItems[mid]?.ts ?? 0) <= checkpoint) lo = mid + 1
      else hi = mid
    }
    filteredItems = lo < allItems.length ? allItems.slice(lo) : []
  } else {
    filteredItems = allItems
  }

  if (last !== null) {
    filteredItems = last === 0 ? [] : filteredItems.slice(-last)
  }

  const responseData = { ...storedData, [appendField]: filteredItems }

  const headers: Record<string, string> = {}
  if (cacheDurationMs != null) {
    const maxAge = Math.floor(cacheDurationMs / 1000)
    const directive = isPublic ? `max-age=${maxAge}` : `private, max-age=${maxAge}`
    headers["Cache-Control"] = directive
  }
  if (storedHash) {
    headers["ETag"] = `"${storedHash}"`
  }

  return { body: { data: responseData, hash: storedHash, timestamp: now }, status: 200, headers: Object.keys(headers).length ? headers : undefined }
}

export interface PushResponse {
  body: Record<string, unknown>
  status: number
}

export async function handleSyncPush(
  documentKey: string,
  store: ObjectStore,
  body: Record<string, unknown>,
  identity?: string | null,
  skipTimestamps: boolean = false,
  skipStorage: boolean = false,
  context?: StoreContext,
): Promise<PushResponse> {
  if (isUnsafeDocumentKey(documentKey)) {
    return { body: { error: "Invalid path parameter" }, status: 400 }
  }

  const data = body["data"]
  const baseHash = body["baseHash"] as string | null | undefined
  const authorSignature = body["authorSignature"] as string | undefined

  if (data == null || typeof data !== "object" || Array.isArray(data)) {
    return { body: { error: "Missing or invalid data" }, status: 400 }
  }

  if (baseHash !== undefined && baseHash !== null && typeof baseHash !== "string") {
    return { body: { error: "baseHash must be a string or null" }, status: 400 }
  }

  const sanitized = deepSanitize(data as Record<string, unknown>)

  let author: Author | undefined
  if (typeof authorSignature === "string" && identity) {
    author = { pubkey: identity, signature: authorSignature }
  }

  const result = await push(
    store,
    documentKey,
    sanitized,
    baseHash ?? null,
    author,
    skipTimestamps,
    skipStorage,
    undefined, // precomputedHash
    context,
  )

  if (!("hash" in result) || !("timestamp" in result)) {
    return { body: { error: ERROR_HASH_MISMATCH }, status: 409 }
  }

  const success = result as PushSuccess
  return { body: { hash: success.hash, timestamp: success.timestamp }, status: 200 }
}
