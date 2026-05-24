/**
 * One-call member eviction.
 *
 * Removing a member from the keyring (`removeRecipient`, which rotates the epoch for
 * forward secrecy) does NOT stop them writing — write authority is cap-based, so the
 * member keeps posting until their cap is revoked. Full eviction is therefore two
 * cryptographic steps plus a roster update, and doing only one is an easy footgun.
 *
 * `evictMember` composes all three behind explicit `rotate` / `revoke` flags so both
 * effects are visible at the call site. It stays transport- and ledger-agnostic: the
 * caller supplies a `submitRevocation` callback (the revocation list's `generation`
 * must strictly increase per issuer, which only the caller can track) and the prior
 * revoked entries to carry forward.
 *
 * For a plaintext / cap-only collection there is no keyring, so eviction is
 * revoke-only: call with `{ rotate: false, revoke: true }` and omit the keyring params.
 * The roster entry (the published cap) is still dropped, cutting off cap distribution —
 * a no-op when no roster exists (e.g. the stateless, out-of-band flow).
 */
import type { StarfishClient } from "@drakkar.software/starfish-client"
import { removeRecipient, type AdderKeys } from "@drakkar.software/starfish-keyring"
import {
  buildRevocationList,
  type RevocationEntry,
  type RevocationList,
} from "@drakkar.software/starfish-protocol"
import { removeMemberEntry } from "./directory.js"

/** The member being evicted, as recorded in the directory + keyring. */
export interface EvictMemberTarget {
  /** Member cap's subject Ed25519 pubkey (hex) — what the revocation names. */
  sub: string
  /** Member cap's nonce (revocation key + directory entry key). */
  nonce: string
  /** Member cap's expiry (unix seconds) — carried into the revocation entry. */
  exp: number
  /** Member's X25519 KEM pubkey (hex) — the keyring recipient to drop. */
  subKem: string
}

export interface EvictMemberParams {
  /**
   * Keyring collection path, e.g. `chatkeyring/rooms/<id>`. Required only when
   * `rotate: true` (the encrypted option). Omit for plaintext / cap-only
   * collections, where eviction is revoke-only — there is no keyring.
   */
  keyringCollection?: string
  /** Member-directory collection path, e.g. `chatmembers/rooms/<id>`. */
  membersCollection: string
  member: EvictMemberTarget
  /** Owner keypair that re-keys the keyring. Required only when `rotate: true`. */
  adder?: AdderKeys
  /** Ed25519 pubkeys trusted to have added keyring recipients. Required only when `rotate: true`. */
  trustedAdders?: string[]
  /** Issuer (owner root) keypair that signs the revocation list. */
  issEdPubHex: string
  issEdPrivHex: string
  /** Strictly-increasing per-issuer revocation generation (caller-owned). */
  generation: number
  /** Previously-revoked entries to carry forward (the store does not merge). */
  priorRevoked?: RevocationEntry[]
  /** Caller-owned transport for the signed list (POST `/revocations`, write a doc, …). */
  submitRevocation: (list: RevocationList) => Promise<void>
}

export interface EvictMemberOpts {
  /** Drop the member from the keyring (rotates the epoch → forward secrecy). */
  rotate: boolean
  /** Revoke the member's cap (server rejects it → stops writes/auth). */
  revoke: boolean
}

export interface EvictMemberResult {
  /** New keyring epoch when `rotate` ran. */
  newEpoch?: number
  /** Whether a revocation list was built and submitted. */
  revoked: boolean
}

/**
 * Evict a member: optionally revoke their cap, optionally rotate them out of the
 * keyring, and (on any eviction) drop their directory entry. Revocation runs FIRST
 * so a still-valid cap cannot squeeze a write in between the rotate and the revoke.
 * With both flags set this is the full, footgun-free eviction.
 */
export async function evictMember(
  client: StarfishClient,
  params: EvictMemberParams,
  opts: EvictMemberOpts,
): Promise<EvictMemberResult> {
  if (!opts.rotate && !opts.revoke) return { revoked: false }

  let revoked = false
  if (opts.revoke) {
    const list = buildRevocationList({
      issEdPubHex: params.issEdPubHex,
      issEdPrivHex: params.issEdPrivHex,
      generation: params.generation,
      revoked: [
        ...(params.priorRevoked ?? []),
        { sub: params.member.sub, nonce: params.member.nonce, exp: params.member.exp },
      ],
    })
    await params.submitRevocation(list)
    revoked = true
  }

  let newEpoch: number | undefined
  if (opts.rotate) {
    if (!params.keyringCollection || !params.adder || !params.trustedAdders) {
      throw new Error(
        "evictMember: rotate=true requires keyringCollection, adder, and trustedAdders " +
          "(omit them only for revoke-only eviction of a plaintext / cap-only collection)",
      )
    }
    const res = await removeRecipient(
      client,
      params.keyringCollection,
      [params.member.subKem],
      params.adder,
      { trustedAdders: params.trustedAdders },
    )
    newEpoch = res.newEpoch
  }

  // Any eviction drops the roster entry — under membership-bound room writes this
  // also removes the member's `chat:member` write grant.
  await removeMemberEntry(client, params.membersCollection, params.member.nonce)

  return { newEpoch, revoked }
}
