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
  bytesToHex,
  getBase64,
  getCrypto,
  hexToBytes,
  signCapCert,
  userIdFromPubHex,
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
}

export const DEFAULT_TTL_SEC = 30 * 24 * 3600
export const NONCE_LEN = 16


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
  const unsigned: UnsignedCapCert = {
    v: 1,
    kind: "device",
    iss: issEdPubHex,
    issUserId: userIdFromPubHex(issEdPubHex),
    sub: sub.edPubHex,
    subKem: sub.kemPubHex,
    scope: { ...scope },
    nbf,
    exp,
    nonce,
  }
  assertCapCertWellFormed(unsigned)
  return signCapCert(unsigned, issEdPrivHex)
}
