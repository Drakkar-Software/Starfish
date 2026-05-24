/**
 * Cap-cert revocation list storage.
 *
 * A revocation list is a signed JSON object identifying a set of cap-cert
 * (sub, nonce) pairs that the issuer wants invalidated before their natural
 * expiry. The list is signed with the issuer's root Ed25519 key — the same
 * key whose pubkey appears as `iss` on the certs themselves.
 *
 * Generation numbers monotonically increase: an accepted list must have a
 * generation strictly greater than the current one for the same issuer.
 * This prevents an attacker who captured an older (less-revoked) list
 * from rolling back the server's view.
 */

import { ed25519 } from "@noble/curves/ed25519.js"
import { stableStringify, getBase64 } from "@drakkar.software/starfish-protocol"

/** A single revoked cap-cert (identified by subject and nonce). */
export interface RevocationEntry {
  /** Subject Ed25519 pubkey of the revoked cap-cert, hex. */
  sub: string
  /** Base64-encoded nonce from the revoked cap-cert. */
  nonce: string
  /**
   * Original expiry of the revoked cap-cert (unix seconds). This is the cap's
   * NATURAL expiry, not the safe pruning time: the resolver honors a cap until
   * `exp + clockSkewSec`, so a persistence/compaction layer that drops the
   * entry at `exp` would un-revoke a cap the resolver still accepts for up to
   * the skew window. Use {@link revocationRetainUntilSec} for the earliest
   * safe prune time.
   */
  exp: number
}

/**
 * A subject-level revocation: invalidates EVERY cap-cert with this `sub` for the
 * issuer, regardless of nonce — the incident-response primitive for a
 * compromised device or member, where re-minting under a fresh nonce would slip
 * past a per-nonce {@link RevocationEntry}. `exp` is the prune-after time the
 * issuer sets: it must be no earlier than the natural expiry of the
 * latest-issued cap for this subject, so durable backends know when the
 * subject-wide revoke can be safely dropped.
 */
export interface RevokedSubject {
  /** Subject Ed25519 pubkey whose every cap (any nonce) is revoked, hex. */
  sub: string
  /** Prune-after time (unix seconds) — see {@link revocationRetainUntilSec}. */
  exp: number
}

/**
 * Clock-skew slop (seconds) the resolver applies when accepting caps — it
 * honors a cap until `cert.exp + clockSkewSec`. Mirrors `verifyCapCert`'s
 * default `clockSkewSec`; a revocation entry must outlive the cap by this much.
 */
export const REVOCATION_RETAIN_SKEW_SEC = 300

/**
 * Earliest unix-second at which a revocation entry may be safely pruned:
 * `entry.exp + skewSec`. Persistence and compaction layers MUST NOT drop an
 * entry before this, otherwise a revoked-but-not-yet-expired cap is honored
 * again during the skew window. The in-memory store here never prunes by time
 * (it keeps each issuer's full list until a higher generation replaces it), so
 * this helper exists for durable backends that do.
 */
export function revocationRetainUntilSec(
  entry: RevocationEntry | RevokedSubject,
  skewSec: number = REVOCATION_RETAIN_SKEW_SEC,
): number {
  return entry.exp + skewSec
}

/** A signed revocation list issued by a root identity. */
export interface RevocationList {
  v: 1
  /** Issuer Ed25519 pubkey, hex. Signatures verify against this key. */
  iss: string
  /** `sha256(iss)[0:32]`. */
  issUserId: string
  /** Monotonically increasing generation counter per issuer. */
  generation: number
  /** Entries naming individual revoked cap-certs. */
  revoked: RevocationEntry[]
  /**
   * Subject-level revocations: every cap with one of these `sub`s (any nonce)
   * is revoked. Optional and omitted by default, so lists that predate this
   * field canonicalize and verify exactly as before. See {@link RevokedSubject}.
   */
  revokedSubjects?: RevokedSubject[]
  /** Ed25519 signature over `stableStringify(list \ sig)`, base64. */
  sig: string
}

/** Pluggable contract for a revocation-list backend. */
export interface RevocationStore {
  /**
   * Returns `true` iff the issuer's current list revokes the cap — either
   * `(capSub, capNonce)` appears in `revoked`, or `capSub` appears in
   * `revokedSubjects` (a subject-wide revoke that covers every nonce).
   */
  isRevoked(iss: string, capSub: string, capNonce: string): boolean
  /**
   * Accept and store a revocation list. Verifies the Ed25519 signature
   * against `list.iss` and rejects lists whose generation is not strictly
   * greater than the currently stored list for that issuer.
   */
  acceptList(list: RevocationList): { ok: true } | { ok: false; reason: string }
}

/** Options for {@link createInMemoryRevocationStore}. */
export interface RevocationStoreOptions {
  /**
   * Hard upper bound on the number of distinct issuers tracked by this
   * in-memory store. Lists for issuers already known are always accepted
   * (they only update existing state). New issuers beyond this cap are
   * rejected with `{ ok: false, reason: "too-many-issuers" }` and a
   * console warning. Default 10 000.
   */
  maxIssuers?: number
}

const DEFAULT_MAX_ISSUERS = 10_000

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex string has odd length")
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
  return out
}

function verifyListSignature(list: RevocationList): boolean {
  try {
    // Strip sig before canonicalizing — same convention as cap-cert signing.
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { sig, ...unsigned } = list
    const canonical = stableStringify(unsigned as unknown as Record<string, unknown>)
    const msg = new TextEncoder().encode(canonical)
    const sigBytes = getBase64().decode(list.sig)
    const pub = hexToBytes(list.iss)
    return ed25519.verify(sigBytes, msg, pub)
  } catch {
    return false
  }
}

/**
 * In-memory revocation store. One signed list is kept per issuer.
 *
 * Lookups consult an internal `Set<string>` of `"${sub}|${nonce}"` keys
 * rebuilt on each `acceptList`, making `isRevoked` O(1) regardless of
 * list size — important because the resolver calls it on every
 * authenticated request.
 *
 * The store also caps the number of distinct issuers it will track (see
 * {@link RevocationStoreOptions.maxIssuers}); existing issuers can always
 * update, but new issuers beyond the cap are rejected.
 */
export function createInMemoryRevocationStore(
  opts: RevocationStoreOptions = {},
): RevocationStore {
  const maxIssuers = opts.maxIssuers ?? DEFAULT_MAX_ISSUERS
  const byIssuer = new Map<string, RevocationList>()
  // Per-issuer set of `"${sub}|${nonce}"` keys — rebuilt on every accepted
  // list so isRevoked() is O(1) instead of an O(n) linear scan.
  const indexByIssuer = new Map<string, Set<string>>()
  // Per-issuer set of subject-wide revoked `sub`s (any nonce), same rationale.
  const subjectsByIssuer = new Map<string, Set<string>>()

  return {
    isRevoked(iss, capSub, capNonce) {
      // An empty `capSub` is the audience-cap sentinel (those caps bind no single
      // subject and are revoked per-nonce). It must NEVER match the subject-wide
      // set, or a stray `revokedSubjects: [{ sub: "" }]` would blanket-revoke
      // every audience cap from that issuer at once. Subject-wide revocation
      // applies to device/member caps, which always carry a non-empty `sub`.
      if (capSub !== "") {
        const subjects = subjectsByIssuer.get(iss)
        if (subjects?.has(capSub)) return true
      }
      const idx = indexByIssuer.get(iss)
      if (!idx) return false
      return idx.has(`${capSub}|${capNonce}`)
    },
    acceptList(list) {
      if (!verifyListSignature(list)) {
        return { ok: false, reason: "bad-signature" }
      }
      const current = byIssuer.get(list.iss)
      if (current && list.generation <= current.generation) {
        return { ok: false, reason: "stale-generation" }
      }
      if (!current && byIssuer.size >= maxIssuers) {
        console.warn(
          `[Starfish] revocation-store: rejecting new issuer ${list.iss.slice(0, 16)}… — maxIssuers cap (${maxIssuers}) reached`,
        )
        return { ok: false, reason: "too-many-issuers" }
      }
      byIssuer.set(list.iss, list)
      // Rebuild the per-issuer lookup indexes. The previous generation's
      // entries are discarded — the new list is authoritative.
      const idx = new Set<string>()
      for (const entry of list.revoked) {
        idx.add(`${entry.sub}|${entry.nonce}`)
      }
      indexByIssuer.set(list.iss, idx)
      const subjects = new Set<string>()
      for (const s of list.revokedSubjects ?? []) {
        subjects.add(s.sub)
      }
      subjectsByIssuer.set(list.iss, subjects)
      return { ok: true }
    },
  }
}
