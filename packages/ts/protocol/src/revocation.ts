/**
 * Build signed v3 revocation lists.
 *
 * A {@link RevocationList} names `(sub, nonce, exp)` cap-cert tuples (and/or whole
 * `revokedSubjects`) revoked by an issuer's root identity. The list is
 * self-authenticating: it carries the issuer's Ed25519 signature over the canonical
 * serialization (`sig` stripped) plus a monotonic `generation` counter, so a server
 * can verify it without a cap and reject stale generations.
 *
 * This is the reusable builder the SDKs and apps were previously forced to hand-roll
 * (the example chat app signed lists inline). It mirrors the Python
 * `build_revocation_list` byte-for-byte — guarded by the shared
 * `tests/test-vectors/revocation-list.json` conformance vector.
 */
import { ed25519 } from "@noble/curves/ed25519.js"
import { sha256 } from "@noble/hashes/sha2.js"
import { getBase64 } from "./platform.js"
import { stableStringify } from "./hash.js"

/** A single revoked cap-cert, identified by its subject + nonce, with the cap's expiry. */
export interface RevocationEntry {
  sub: string
  nonce: string
  exp: number
}

/** Revokes every cap with this subject (incident-response fallback). */
export interface RevokedSubject {
  sub: string
  exp: number
}

/** A signed, generation-counted revocation list issued by a root identity. */
export interface RevocationList {
  v: 1
  iss: string
  issUserId: string
  generation: number
  revoked: RevocationEntry[]
  revokedSubjects?: RevokedSubject[]
  /** Ed25519 signature over the canonical signing input, base64-encoded. */
  sig: string
}

export interface BuildRevocationListOpts {
  issEdPubHex: string
  issEdPrivHex: string
  generation: number
  revoked: RevocationEntry[]
  revokedSubjects?: RevokedSubject[]
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex string has odd length")
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
  return out
}

function bytesToHex(bytes: Uint8Array): string {
  let s = ""
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, "0")
  return s
}

function userIdFromPubHex(pubHex: string): string {
  return bytesToHex(sha256(hexToBytes(pubHex))).slice(0, 32)
}

/**
 * Canonical signing input for a revocation list: `stableStringify` of the list
 * with `sig` stripped. Byte-for-byte identical to the Python
 * `revocation_list_canonical_signing_input`.
 */
export function revocationListCanonicalSigningInput(
  list: Omit<RevocationList, "sig"> | RevocationList,
): string {
  const unsigned: Record<string, unknown> = { ...(list as Record<string, unknown>) }
  delete unsigned.sig
  return stableStringify(unsigned)
}

/**
 * Build and sign a {@link RevocationList}. `issUserId` is derived as
 * `sha256(issEdPub)[0:32]`; `revokedSubjects` is included (and signed) only when
 * supplied.
 */
export function buildRevocationList(opts: BuildRevocationListOpts): RevocationList {
  const unsigned: Omit<RevocationList, "sig"> = {
    v: 1,
    iss: opts.issEdPubHex,
    issUserId: userIdFromPubHex(opts.issEdPubHex),
    generation: opts.generation,
    revoked: opts.revoked,
    ...(opts.revokedSubjects !== undefined ? { revokedSubjects: opts.revokedSubjects } : {}),
  }
  const message = new TextEncoder().encode(revocationListCanonicalSigningInput(unsigned))
  const sigBytes = ed25519.sign(message, hexToBytes(opts.issEdPrivHex))
  return { ...unsigned, sig: getBase64().encode(sigBytes) }
}
