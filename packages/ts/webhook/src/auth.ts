/**
 * Generic HMAC authentication for an inbound webhook caller.
 *
 * The scheme is intentionally provider-neutral: HMAC-SHA256 over the raw body
 * (or `${timestamp}.${raw}` when a timestamp header is configured), hex-encoded,
 * compared in constant time. Most webhook senders can produce this, and a
 * configured timestamp header bounds replay without any server-side nonce store.
 */

import { bytesToHex, getCrypto } from "@drakkar.software/starfish-protocol"
import type { HmacAuthConfig } from "./types.js"

const ENC = new TextEncoder()
const DEFAULT_SIGNATURE_HEADER = "x-webhook-signature"
const DEFAULT_TOLERANCE_SECONDS = 300

async function hmacHex(secret: string, message: string): Promise<string> {
  // The protocol `CryptoProvider` narrows `subtle` to the few operations the core
  // needs (no HMAC); cast to the full WebCrypto surface, as the keyring does.
  const subtle = getCrypto().subtle as unknown as SubtleCrypto
  const key = await subtle.importKey(
    "raw",
    ENC.encode(secret) as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  )
  const sig = await subtle.sign("HMAC", key, ENC.encode(message) as BufferSource)
  return bytesToHex(new Uint8Array(sig))
}

/** Constant-time hex-string comparison. Returns `false` immediately on a length
 *  mismatch (the expected length is a fixed 64 hex chars, not a secret), but never
 *  short-circuits on content, so it leaks no information about WHERE bytes differ. */
function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

/** Outcome of {@link verifyHmac}: `ok`, or a rejection with an HTTP status. */
export type AuthResult = { ok: true } | { ok: false; status: number; error: string }

/**
 * Verify a webhook request's HMAC. `raw` is the exact body; `headers` keys must be
 * lowercased. On success returns `{ ok: true }`; otherwise a `401` (or the
 * configured status) with a terse reason — reasons never echo the secret or the
 * computed signature.
 */
export async function verifyHmac(
  cfg: HmacAuthConfig,
  raw: string,
  headers: Record<string, string>,
): Promise<AuthResult> {
  // Fail closed on a missing/empty secret — a misconfigured route must never become
  // an open endpoint (an empty secret still yields a computable, "valid" HMAC).
  if (!cfg.secret) return { ok: false, status: 500, error: "webhook_misconfigured" }
  const sigHeaderName = (cfg.signatureHeader ?? DEFAULT_SIGNATURE_HEADER).toLowerCase()
  const provided = headers[sigHeaderName]
  if (!provided) return { ok: false, status: 401, error: "missing_signature" }

  let message = raw
  if (cfg.timestampHeader) {
    const tsRaw = headers[cfg.timestampHeader.toLowerCase()]
    if (!tsRaw) return { ok: false, status: 401, error: "missing_timestamp" }
    const ts = Number(tsRaw)
    if (!Number.isFinite(ts)) return { ok: false, status: 401, error: "invalid_timestamp" }
    const tolerance = cfg.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS
    const ageSeconds = Math.abs(Math.floor(Date.now() / 1000) - ts)
    if (ageSeconds > tolerance) return { ok: false, status: 401, error: "timestamp_out_of_tolerance" }
    message = `${tsRaw}.${raw}`
  }

  const expected = await hmacHex(cfg.secret, message)
  if (!timingSafeEqualHex(expected, provided.trim().toLowerCase())) {
    return { ok: false, status: 401, error: "invalid_signature" }
  }
  return { ok: true }
}
