/**
 * Shared building blocks for the space + node invite / link / accept / revoke flows.
 *
 * One implementation per concept, reused across both tiers (members.ts and nodes.ts),
 * parameterized by collection + scope. Keeps the security-critical *policy* (which
 * scope, which keyring) at the call sites while removing the repeated boilerplate.
 */
import { generateDeviceKeys } from "@drakkar.software/starfish-identities"
import type { ScopePreset } from "@drakkar.software/starfish-identities"
import { mintMemberCap, evictMember } from "@drakkar.software/starfish-sharing"
import type { MintOpts } from "@drakkar.software/starfish-sharing"
import type { CapCert, RevocationEntry, RevocationList } from "@drakkar.software/starfish-protocol"
import type { StarfishClient } from "@drakkar.software/starfish-client"

import type { Session } from "./session.js"
import { ownerTrustedAdders } from "./session.js"
import { verifyKemSig } from "./request-verify.js"
import type { JoinRequest } from "./token-types.js"

/** The `{ edPubHex, kemPubHex, userIdHex }` subject passed to `mintMemberCap`. */
export type CapSubject = { edPubHex: string; kemPubHex: string; userIdHex: string }

/** The keyring adder / revocation signer triple from the session device keys. */
export const adderOf = (session: Session) => ({
  edPriv: session.keys.edPriv,
  edPub: session.keys.edPub,
  kemPriv: session.keys.kemPriv,
})

/** Mint a member cap signed by the session, for `subject` over one collection + scope. */
export const mintCap = (session: Session, subject: CapSubject, collection: string, scope: ScopePreset, opts?: MintOpts): Promise<unknown> =>
  mintMemberCap(session.keys.edPriv, session.keys.edPub, subject, collection, scope, opts)

/** The retained `{ nonce, exp }` for a freshly-minted cap, or undefined if it carries none. */
export function capNonce(cap: unknown): { nonce: string; exp: number } | undefined {
  const cert = cap as CapCert | undefined
  return cert?.nonce ? { nonce: cert.nonce, exp: cert.exp } : undefined
}

/**
 * Reject a cap that has expired or is not yet valid, based on its `nbf`/`exp`
 * (unix seconds). The server enforces `nbf`/`exp` on every request regardless;
 * this gives link redemption a clear, immediate error instead of a silent
 * post-join pull failure. A cap carrying no `exp` (should not happen for a
 * minted member cap) is treated as non-expiring — the server stays the backstop.
 */
export function assertCapNotExpired(cap: unknown, errPrefix: string): void {
  const cert = cap as { nbf?: number; exp?: number } | undefined
  const now = Math.floor(Date.now() / 1000)
  if (cert?.nbf != null && now < cert.nbf) throw new Error(`${errPrefix}: this invite link is not yet valid.`)
  if (cert?.exp != null && now >= cert.exp) throw new Error(`${errPrefix}: this invite link has expired.`)
}

/**
 * Parse + fully verify a join request: shape, `userId === sha256(edPub)`, and kemSig.
 * Throws `${errPrefix}.` / `${errPrefix}: userId does not match edPub.` /
 * `${errPrefix}: kemSig is missing or invalid.`
 */
export async function parseJoinRequest(requestJson: string, errPrefix: string, session: Session): Promise<JoinRequest> {
  const req = JSON.parse(requestJson) as JoinRequest
  if (!req.edPub || !req.kemPub || !req.userId) throw new Error(`${errPrefix}.`)
  if ((await session.userIdFromEdPub(req.edPub)) !== req.userId) throw new Error(`${errPrefix}: userId does not match edPub.`)
  if (!verifyKemSig(req.edPub, req.kemPub, req.kemSig)) throw new Error(`${errPrefix}: kemSig is missing or invalid.`)
  return req
}

/** Generate a throwaway ephemeral Ed/KEM keypair + its derived userId and cap subject. */
export async function ephemeralSubject(session: Session): Promise<{
  ek: ReturnType<typeof generateDeviceKeys>
  userId: string
  subject: CapSubject
}> {
  const ek = generateDeviceKeys()
  const userId = await session.userIdFromEdPub(ek.edPub)
  return { ek, userId, subject: { edPubHex: ek.edPub, kemPubHex: ek.kemPub, userIdHex: userId } }
}

/** Assert a present cap was a `member` cap issued for `myEdPub`. Returns false when the
 *  cap is absent (caller decides if that's allowed); throws the given messages when it is
 *  present-but-wrong. */
export function assertCapForMe(
  cap: { kind?: string; sub?: string } | undefined,
  myEdPub: string,
  kindMsg: string,
  identityMsg: string,
): boolean {
  if (!cap) return false
  if (cap.kind !== "member") throw new Error(kindMsg)
  if (!cap.sub || cap.sub !== myEdPub) throw new Error(identityMsg)
  return true
}

/**
 * Full eviction of one keyring member: rotate the keyring (forward secrecy) AND submit a
 * signed RevocationList for their cap(s). Holds the boilerplate shared byte-for-byte by
 * `revokeSpaceAccess` and `revokeNodeAccess`; each caller supplies the collection, the
 * member's primary nonce source, and any extra `priorRevoked` nonces.
 */
export function evictKeyringMember(
  client: StarfishClient,
  session: Session,
  keyringCollection: string,
  member: { sub: string; nonce: string; exp: number; subKem: string },
  opts: { generation: number; priorRevoked?: RevocationEntry[]; submitRevocation: (list: RevocationList) => Promise<void> },
): Promise<{ newEpoch?: number; revoked: boolean }> {
  const priorRevoked = opts.priorRevoked ?? []
  return evictMember(
    client,
    {
      keyringCollection,
      membersCollection: keyringCollection,
      member,
      adder: adderOf(session),
      trustedAdders: ownerTrustedAdders(session),
      issEdPubHex: session.keys.edPub,
      issEdPrivHex: session.keys.edPriv,
      generation: opts.generation,
      ...(priorRevoked.length > 0 ? { priorRevoked } : {}),
      submitRevocation: opts.submitRevocation,
    },
    { rotate: true, revoke: true },
  )
}
