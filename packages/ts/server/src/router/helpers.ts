import * as net from "node:net"
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

export function validateUrlNotPrivate(url: string): boolean {
  try {
    const parsed = new URL(url)
    const hostname = parsed.hostname
    if (!hostname) return false
    if (["localhost", "127.0.0.1", "::1", "0.0.0.0"].includes(hostname)) return false
    const ipVersion = net.isIP(hostname)
    if (ipVersion === 4) {
      const parts = hostname.split(".").map(Number)
      // 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x, 169.254.x.x
      if (
        parts[0] === 10 ||
        parts[0] === 127 ||
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
        (parts[0] === 192 && parts[1] === 168) ||
        (parts[0] === 169 && parts[1] === 254)
      ) {
        return false
      }
    } else if (ipVersion === 6) {
      // Normalize: strip brackets, expand to check prefixes
      const addr = hostname.replace(/^\[|\]$/g, "").toLowerCase()
      // fc00::/7 (unique local), fe80::/10 (link-local), ::1 (loopback)
      if (addr.startsWith("fc") || addr.startsWith("fd") || addr.startsWith("fe80") || addr === "::1") {
        return false
      }
    }
    return true
  } catch {
    return false
  }
}

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

/** Parse and validate a checkpoint query param. Returns the numeric value or an error Response. */
export function parseCheckpoint(param: string): number | Response {
  const parsed = parseInt(param, 10)
  if (isNaN(parsed) || parsed < 0 || String(parsed) !== param) {
    return Response.json({ error: "Invalid checkpoint" }, { status: 400 })
  }
  return parsed
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
    const result = parseCheckpoint(opts.checkpointParam)
    if (result instanceof Response) return result
    checkpoint = result
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
