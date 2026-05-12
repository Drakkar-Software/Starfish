import type { ObjectStore, StoreContext } from "../storage/base.js"
import { pull } from "../protocol/pull.js"
import { push, type Author } from "../protocol/push.js"
import type { PushSuccess, StoredDocument } from "../protocol/types.js"
import { stableStringify } from "@drakkar.software/starfish-protocol"
import { ERROR_HASH_MISMATCH } from "../constants.js"

const SAFE_PARAM = /^[a-zA-Z0-9._:@-]+$/
const UNSAFE_KEY = /\.\.|[\x00-\x1f]|\/\//
const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"])

export type SignatureVerifier = (
  canonical: string,
  signature: string,
  identity: string,
) => Promise<boolean>

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

export interface PullResponse {
  body: Record<string, unknown>
  status: number
  headers?: Record<string, string>
}

export async function handleSyncPull(
  documentKey: string,
  store: ObjectStore,
  checkpointParam?: string | null,
  forceFullFetch: boolean = false,
  clientEncrypted: boolean = false,
  cacheDurationMs?: number,
  isPublic: boolean = true,
  context?: StoreContext,
): Promise<PullResponse> {
  if (UNSAFE_KEY.test(documentKey)) {
    return { body: { error: "Invalid path parameter" }, status: 400 }
  }

  let checkpoint = 0
  if (!forceFullFetch && !clientEncrypted && checkpointParam != null) {
    const parsed = parseInt(checkpointParam, 10)
    if (isNaN(parsed) || parsed < 0 || String(parsed) !== checkpointParam) {
      return { body: { error: "Invalid checkpoint" }, status: 400 }
    }
    checkpoint = parsed
  }

  const result = await pull(store, documentKey, checkpoint, context)
  const body: Record<string, unknown> = {
    data: result.data,
    hash: result.hash,
    timestamp: result.timestamp,
  }
  if (result.authorPubkey) body["authorPubkey"] = result.authorPubkey
  if (result.authorSignature) body["authorSignature"] = result.authorSignature

  let headers: Record<string, string> | undefined
  if (cacheDurationMs != null) {
    const maxAge = Math.floor(cacheDurationMs / 1000)
    const directive = isPublic ? `max-age=${maxAge}` : `private, max-age=${maxAge}`
    headers = { "Cache-Control": directive }
  }

  return { body, status: 200, headers }
}

/**
 * Pull handler for appendOnly persist=true collections.
 *
 * When a checkpoint is requested, filters data[appendField] to only items
 * whose per-item timestamp (stored as a number[] parallel to the array)
 * is greater than the checkpoint. Falls back to returning the full array for
 * legacy docs without per-item timestamps.
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
  if (UNSAFE_KEY.test(documentKey)) {
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
  const allItems = Array.isArray(storedData[appendField]) ? (storedData[appendField] as unknown[]) : []

  let filteredItems: unknown[]
  if (checkpoint > 0) {
    const storedTs = stored.timestamps?.[appendField]
    if (Array.isArray(storedTs)) {
      // Timestamps are monotonically non-decreasing — binary search for first index > checkpoint
      const ts = storedTs as number[]
      let lo = 0, hi = ts.length
      while (lo < hi) {
        const mid = (lo + hi) >>> 1
        if ((ts[mid] ?? 0) <= checkpoint) lo = mid + 1
        else hi = mid
      }
      filteredItems = lo < allItems.length ? allItems.slice(lo) : []
    } else {
      // Legacy doc without per-item timestamps: return full array (checkpoint not applicable)
      filteredItems = allItems
    }
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
  verifySignature?: SignatureVerifier,
  skipTimestamps: boolean = false,
  skipStorage: boolean = false,
  context?: StoreContext,
): Promise<PushResponse> {
  if (UNSAFE_KEY.test(documentKey)) {
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
  if (verifySignature && identity) {
    if (typeof authorSignature !== "string") {
      return { body: { error: "Missing required author signature" }, status: 400 }
    }
    const canonical = stableStringify(sanitized)
    const valid = await verifySignature(canonical, authorSignature, identity)
    if (!valid) {
      return { body: { error: "Invalid author signature" }, status: 400 }
    }
    author = { pubkey: identity, signature: authorSignature }
  } else if (typeof authorSignature === "string" && identity) {
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
    undefined,
    undefined,
    context,
  )

  if (!("hash" in result) || !("timestamp" in result)) {
    return { body: { error: ERROR_HASH_MISMATCH }, status: 409 }
  }

  const success = result as PushSuccess
  return { body: { hash: success.hash, timestamp: success.timestamp }, status: 200 }
}
