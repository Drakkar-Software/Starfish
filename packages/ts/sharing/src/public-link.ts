/**
 * Public-link API for plaintext (cap-only) sharing.
 *
 * A public link is an `audience` cap-cert packed into a URL `#fragment`. Unlike
 * a `member` cap it binds **no** single subject: every redeemer signs requests
 * with their **own** identity key (named via the `X-Starfish-Pub` header), so
 * writes are attributable per user. An optional allow-list (`allowedIdentities`)
 * narrows who may redeem; when omitted, any identity may. No private key is ever
 * embedded in the link.
 *
 * Flow:
 *   owner:    `createPublicLink(...)`  → share `link#<fragment>`
 *   redeemer: `parsePublicLink(fragment)` → `redeemPublicLink(parsed, ...)`
 *             → send the returned headers with each request.
 *
 * `parsePublicLink` shape-checks the embedded cap but does NOT verify its
 * signature or expiry — that is the server's job at request time.
 */

import {
  getBase64,
  signRequest,
  stableStringify,
  type CapCert,
  type SignableMethod,
  type SignableRequest,
} from "@drakkar.software/starfish-protocol"
import {
  assertAudienceCapShape,
  mintAudienceCap,
  type ScopePreset,
} from "./cap-mint.js"

/** Current public-link payload version. */
const PUBLIC_LINK_V = 1

/** Options for {@link createPublicLink}. */
export interface CreatePublicLinkOpts {
  /** Issuer (collection owner) Ed25519 private key, hex. */
  issEdPrivHex: string
  /** Issuer Ed25519 public key, hex. */
  issEdPubHex: string
  /** Single collection the link grants access to. */
  collection: string
  /** Scope preset (e.g. `scopes.readOnly(col)` / `scopes.writer(col)`). */
  scope: ScopePreset
  /**
   * Optional allow-list of redeemer Ed25519 pubkeys (64-char lowercase hex).
   * Omit for "any identity may redeem"; provide to restrict to these identities.
   */
  allowedIdentities?: string[]
  /** Absolute expiry, unix seconds. Wins over `ttlSec`. Must be after `nbf`. */
  expiresAt?: number
  /** TTL in seconds from `nbf`. Defaults to 30 days when neither this nor `expiresAt` is set. */
  ttlSec?: number
  /** Not-before, unix seconds. Defaults to now. */
  nbf?: number
  /** Random nonce bytes (16 recommended). Defaults to fresh randomness. */
  nonce?: Uint8Array
}

/** Result of {@link createPublicLink}. */
export interface PublicLink {
  /** base64url payload to place after the `#` in a share URL. */
  fragment: string
  /** The minted audience cap-cert (also embedded in `fragment`). */
  cap: CapCert
}

/** Result of {@link parsePublicLink}. */
export interface ParsedPublicLink {
  /** The audience cap-cert carried by the link. */
  cap: CapCert
}

/** Options for {@link redeemPublicLink}. */
export interface RedeemPublicLinkOpts {
  /** The redeemer's own Ed25519 private key, hex (must match `redeemerEdPubHex`). */
  redeemerEdPrivHex: string
  /** The redeemer's own Ed25519 public key, hex — sent as `X-Starfish-Pub`. */
  redeemerEdPubHex: string
  /** HTTP method of the request being signed. */
  method: SignableMethod
  /** Path + query of the request being signed (e.g. `/pull/broadcast/abc`). */
  pathAndQuery: string
  /** Request body (signed). A JSON write signs its body; a blob upload signs empty. */
  body?: Uint8Array | string
  /** Host the request is bound to (folded into the signature). */
  host?: string
  /** Override signing timestamp (unix ms). Defaults to now. */
  ts?: number
  /** Override signing nonce (16 bytes). Defaults to fresh randomness. */
  nonce?: Uint8Array
}

/** Header set a client sends to redeem a public link. */
export interface RedeemHeaders {
  Authorization: string
  "X-Starfish-Sig": string
  "X-Starfish-Ts": string
  "X-Starfish-Nonce": string
  "X-Starfish-Pub": string
}

interface PublicLinkPayload {
  v: number
  cap: CapCert
}

// ── base64url (URL-fragment-safe) ──────────────────────────────────────────────
// Standard base64 (`+`, `/`, `=`) is unsafe in a URL fragment; map to base64url
// and strip padding. The exact same mapping is used by create + parse and is
// mirrored byte-for-byte in Python's `public_link.py`.

function b64urlEncode(s: string): string {
  const std = getBase64().encode(new TextEncoder().encode(s))
  return std.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

function b64urlDecode(s: string): string {
  let std = s.replace(/-/g, "+").replace(/_/g, "/")
  const rem = std.length % 4
  if (rem === 2) std += "=="
  else if (rem === 3) std += "="
  else if (rem === 1) throw new Error("malformed public link: bad base64url length")
  return new TextDecoder().decode(getBase64().decode(std))
}

/** Encode a cap-cert for the `Authorization: Cap <…>` header (matches the resolver). */
function encodeCapAuth(cap: CapCert): string {
  return getBase64().encode(new TextEncoder().encode(stableStringify(cap as unknown as Record<string, unknown>)))
}

/**
 * Mint an audience cap and pack it into a shareable URL fragment.
 *
 * With `allowedIdentities` the link works only for those identities; without
 * it, any identity may redeem. Either way the link carries no private key.
 */
export async function createPublicLink(opts: CreatePublicLinkOpts): Promise<PublicLink> {
  const cap = await mintAudienceCap(opts.issEdPrivHex, opts.issEdPubHex, opts.collection, opts.scope, {
    audience: opts.allowedIdentities,
    expiresAt: opts.expiresAt,
    ttlSec: opts.ttlSec,
    nbf: opts.nbf,
    nonce: opts.nonce,
  })
  const payload: PublicLinkPayload = { v: PUBLIC_LINK_V, cap }
  const fragment = b64urlEncode(stableStringify(payload as unknown as Record<string, unknown>))
  return { fragment, cap }
}

/**
 * Decode and shape-check a public-link fragment. Does NOT verify the cap's
 * signature or expiry — the server does that at request time. Throws on a
 * malformed fragment, wrong payload version, or a non-audience / malformed cap.
 */
export function parsePublicLink(fragment: string): ParsedPublicLink {
  let payload: unknown
  try {
    payload = JSON.parse(b64urlDecode(fragment.trim()))
  } catch {
    throw new Error("malformed public link: invalid fragment encoding")
  }
  if (typeof payload !== "object" || payload === null) {
    throw new Error("malformed public link: payload is not an object")
  }
  const p = payload as { v?: unknown; cap?: unknown }
  if (p.v !== PUBLIC_LINK_V) {
    throw new Error(`unsupported public link version: ${String(p.v)}`)
  }
  const cap = p.cap as CapCert | undefined
  if (typeof cap !== "object" || cap === null || cap.kind !== "audience") {
    throw new Error("malformed public link: cap is not an audience cap")
  }
  // Structural validation only (no signature/expiry check — server's job).
  assertAudienceCapShape(cap)
  return { cap }
}

/**
 * Build the header set a redeemer sends with each request, signing with the
 * redeemer's own key and naming it via `X-Starfish-Pub`. Transport-agnostic:
 * the caller attaches these headers to its HTTP request.
 *
 * The body passed here MUST equal the bytes sent on the wire so the signature
 * the server reconstructs matches.
 */
export async function redeemPublicLink(
  parsed: ParsedPublicLink,
  opts: RedeemPublicLinkOpts,
): Promise<RedeemHeaders> {
  const req: SignableRequest = {
    method: opts.method,
    pathAndQuery: opts.pathAndQuery,
    body: opts.body,
    host: opts.host,
  }
  const { sig, ts, nonce } = await signRequest(req, opts.redeemerEdPrivHex, {
    ts: opts.ts,
    nonce: opts.nonce,
  })
  return {
    Authorization: `Cap ${encodeCapAuth(parsed.cap)}`,
    "X-Starfish-Sig": sig,
    "X-Starfish-Ts": String(ts),
    "X-Starfish-Nonce": nonce,
    "X-Starfish-Pub": opts.redeemerEdPubHex,
  }
}
