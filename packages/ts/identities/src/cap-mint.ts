/**
 * Device cap-cert minting helpers (and the shared scope-preset helpers used by
 * both the identities and sharing extensions).
 *
 * Higher-level convenience over the protocol package's `signCapCert` /
 * `assertCapCertWellFormed`. The mint helpers do the boilerplate: build the
 * unsigned cert, derive `issUserId` from the issuer pubkey, fill `nbf`/`exp`,
 * generate the nonce, run the well-formedness check, and finally sign.
 */

import {
  assertCapCertWellFormed,
  DEFAULT_ALG,
  getBase64,
  getCrypto,
  signCapCert,
  suiteHasSeparateKem,
  type Alg,
  type CapCert,
  type UnsignedCapCert,
} from "@drakkar.software/starfish-protocol"

/** Operations + paths + collections a minted cap-cert authorizes. */
export interface ScopePreset {
  ops: ("read" | "write" | "list")[]
  collections: string[]
  paths?: string[]
}

/** Built-in scope presets exposed by this package (device-side).
 *
 *  Member-scoped presets (`readOnly`, `writer`, `admin`) live in
 *  `@drakkar.software/starfish-sharing`.
 */
export const scopes = {
  /** Root-grade access to everything — used for device caps. */
  rootAll: (): ScopePreset => ({
    ops: ["read", "list", "write"],
    paths: ["**"],
    collections: ["*"],
  }),
}

/** Optional knobs for the mint helpers. */
export interface MintOpts {
  /** TTL in seconds. Default 30 days. */
  ttlSec?: number
  /** Not-before, unix seconds. Defaults to `Math.floor(Date.now()/1000)`. */
  nbf?: number
  /** Random nonce bytes (16 recommended). Defaults to fresh randomness. */
  nonce?: Uint8Array
  /** Issuer's crypto suite (governs the cap signature). Defaults to the system default. */
  alg?: Alg
  /** Subject's signing suite (governs `sub` + per-request sigs). Defaults to `alg`. */
  subAlg?: Alg
  /** Subject's KEM suite (governs `subKem`). Defaults to `subAlg`. */
  subKemAlg?: Alg
}

export const DEFAULT_TTL_SEC = 30 * 24 * 3600
export const NONCE_LEN = 16

export function bytesToHex(bytes: Uint8Array): string {
  let s = ""
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, "0")
  return s
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex string has odd length")
  // Reject non-hex chars: `parseInt` → NaN → 0, silently zeroing malformed input.
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error("hex string has invalid characters")
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
  return out
}

export async function userIdFromPubHex(pubHex: string): Promise<string> {
  const pubBytes = hexToBytes(pubHex)
  const digest = await getCrypto().subtle.digest("SHA-256", pubBytes as BufferSource)
  return bytesToHex(new Uint8Array(digest)).slice(0, 32)
}

export function defaultNonce(): Uint8Array {
  const buf = new Uint8Array(NONCE_LEN)
  getCrypto().getRandomValues(buf)
  return buf
}

/**
 * Mint a `device` cap-cert: the subject acts as a proxy for the issuer.
 *
 * The minted cert is well-formed by construction; on a malformed input
 * (e.g. mismatched userId) the underlying `assertCapCertWellFormed` will
 * throw an `Error` with a `.code` property describing the failure.
 */
export async function mintDeviceCap(
  issEdPrivHex: string,
  issEdPubHex: string,
  sub: { edPubHex: string; kemPubHex: string },
  scope: ScopePreset,
  opts: MintOpts = {},
): Promise<CapCert> {
  const nbf = opts.nbf ?? Math.floor(Date.now() / 1000)
  const exp = nbf + (opts.ttlSec ?? DEFAULT_TTL_SEC)
  const nonceBytes = opts.nonce ?? defaultNonce()
  const nonce = getBase64().encode(nonceBytes)
  const issAlg = opts.alg ?? DEFAULT_ALG
  const subAlg = opts.subAlg ?? issAlg
  const subKemAlg = opts.subKemAlg ?? subAlg
  // subKem is omitted only when the KEM key IS the signing key (same suite +
  // single-key suite); otherwise it carries a distinct KEM pubkey of suite
  // `subKemAlg`. The keyring now wraps under any registered suite's ECDH (see
  // `recipientKem`), so every `subKemAlg` is mintable.
  const kemKeyIsSignKey = subKemAlg === subAlg && !suiteHasSeparateKem(subKemAlg)
  const unsigned: UnsignedCapCert = {
    v: 1,
    kind: "device",
    issAlg,
    subAlg,
    ...(opts.subKemAlg !== undefined && opts.subKemAlg !== subAlg ? { subKemAlg } : {}),
    iss: issEdPubHex,
    issUserId: await userIdFromPubHex(issEdPubHex),
    sub: sub.edPubHex,
    ...(kemKeyIsSignKey ? {} : { subKem: sub.kemPubHex }),
    scope: { ...scope },
    nbf,
    exp,
    nonce,
  }
  assertCapCertWellFormed(unsigned)
  return signCapCert(unsigned, issEdPrivHex)
}
