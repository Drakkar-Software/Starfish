import { stableStringify } from "@starfish/protocol"
import type { AbstractObjectStore } from "../storage/base.js"
import { pull } from "../protocol/pull.js"
import { push, type Author } from "../protocol/push.js"
import { isPushConflict } from "../protocol/types.js"
import { ERROR_HASH_MISMATCH, CONTENT_TYPE_JSON } from "../constants.js"

const SAFE_PARAM = /^[a-zA-Z0-9._:@-]+$/
const UNSAFE_KEY_PATTERN = /\.\.|[\x00-\x1f]|\/\//

const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"])

export type SignatureVerifier = (
  canonical: string,
  signature: string,
  identity: string,
) => Promise<boolean>

export function validatePathSegment(value: string): boolean {
  return SAFE_PARAM.test(value)
}

export function deepSanitize(obj: Record<string, unknown>): Record<string, unknown> {
  const safe: Record<string, unknown> = {}
  for (const [key, val] of Object.entries(obj)) {
    if (UNSAFE_KEYS.has(key)) continue
    if (val && typeof val === "object" && !Array.isArray(val)) {
      safe[key] = deepSanitize(val as Record<string, unknown>)
    } else {
      safe[key] = val
    }
  }
  return safe
}

export interface SyncPullOptions {
  documentKey: string
  store: AbstractObjectStore
  checkpointParam?: string | null
  forceFullFetch?: boolean
  clientEncrypted?: boolean
  cacheDurationMs?: number | null
  isPublic?: boolean
}

export async function handleSyncPull(
  opts: SyncPullOptions,
): Promise<Response> {
  if (UNSAFE_KEY_PATTERN.test(opts.documentKey)) {
    return Response.json({ error: "Invalid path parameter" }, { status: 400 })
  }

  let checkpoint = 0
  if (
    !opts.forceFullFetch &&
    !opts.clientEncrypted &&
    opts.checkpointParam != null
  ) {
    const parsed = parseInt(opts.checkpointParam, 10)
    if (isNaN(parsed) || parsed < 0 || String(parsed) !== opts.checkpointParam) {
      return Response.json({ error: "Invalid checkpoint" }, { status: 400 })
    }
    checkpoint = parsed
  }

  const result = await pull(opts.store, opts.documentKey, checkpoint)
  const body: Record<string, unknown> = {
    data: result.data,
    hash: result.hash,
    timestamp: result.timestamp,
  }
  if (result.authorPubkey) body.authorPubkey = result.authorPubkey
  if (result.authorSignature) body.authorSignature = result.authorSignature

  const headers: Record<string, string> = { "Content-Type": CONTENT_TYPE_JSON }
  if (opts.cacheDurationMs != null) {
    const maxAge = Math.floor(opts.cacheDurationMs / 1000)
    headers["Cache-Control"] =
      opts.isPublic !== false ? `max-age=${maxAge}` : `private, max-age=${maxAge}`
  }

  return new Response(JSON.stringify(body), { status: 200, headers })
}

export interface SyncPushOptions {
  documentKey: string
  store: AbstractObjectStore
  body: Record<string, unknown>
  identity?: string | null
  verifySignature?: SignatureVerifier | null
  skipTimestamps?: boolean
}

export async function handleSyncPush(
  opts: SyncPushOptions,
): Promise<Response> {
  if (UNSAFE_KEY_PATTERN.test(opts.documentKey)) {
    return Response.json({ error: "Invalid path parameter" }, { status: 400 })
  }

  const data = opts.body.data
  const baseHash = opts.body.baseHash as string | null | undefined
  const authorSignature = opts.body.authorSignature as string | undefined

  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return Response.json({ error: "Missing or invalid data" }, { status: 400 })
  }

  if (baseHash !== null && baseHash !== undefined && typeof baseHash !== "string") {
    return Response.json({ error: "baseHash must be a string or null" }, { status: 400 })
  }

  const sanitized = deepSanitize(data as Record<string, unknown>)

  let author: Author | undefined
  if (opts.verifySignature && opts.identity) {
    if (typeof authorSignature !== "string") {
      return Response.json({ error: "Missing required author signature" }, { status: 400 })
    }
    const canonical = stableStringify(sanitized)
    const valid = await opts.verifySignature(canonical, authorSignature, opts.identity)
    if (!valid) {
      return Response.json({ error: "Invalid author signature" }, { status: 400 })
    }
    author = { pubkey: opts.identity, signature: authorSignature }
  } else if (typeof authorSignature === "string" && opts.identity) {
    author = { pubkey: opts.identity, signature: authorSignature }
  }

  const result = await push(
    opts.store,
    opts.documentKey,
    sanitized,
    baseHash ?? null,
    author,
    opts.skipTimestamps ?? false,
  )

  if (isPushConflict(result)) {
    return Response.json({ error: ERROR_HASH_MISMATCH }, { status: 409 })
  }

  return Response.json({ hash: result.hash, timestamp: result.timestamp })
}
