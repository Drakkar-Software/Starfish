/**
 * Space membership — invite-based (member cap) and link-based (open access).
 *
 * MEMBER join: the owner records the invitee in the roster, mints a space-scoped
 * member cap, and adds the invitee to the space-wide keyring (if it exists) so they
 * can decrypt `enc` content. The invitee stores a `{kind:'member'}` entry.
 *
 * LINK join: the owner mints an ephemeral Ed/KEM keypair whose *private* key ships
 * inside a URL-fragment token, adds the ephemeral userId to the roster so the server
 * grants `space:member`, and mints a member cap scoped to that ephemeral subject.
 * Any bearer of the link stores a `{kind:'link'}` entry.
 *
 * REVOCATION (roster-only): `removeSpaceMember` removes the userId from the server
 * roster so the server stops granting `space:member` to new requests. This alone is
 * sufficient for non-encrypted spaces. For `enc` spaces call `revokeSpaceAccess`
 * instead — it rotates the space keyring (forward secrecy) AND submits a signed
 * RevocationList so the server immediately rejects the evicted member's cap.
 *
 * DEVICE PAIRING: after pairing, call `addDeviceToSpaceKeyring(session, spaceId, device)`
 * for each space the paired device should decrypt. ONE keyring per space encrypts all
 * `enc` nodes; adding the device once unlocks the whole space's E2EE content.
 */
import type { RevocationEntry, RevocationList } from "@drakkar.software/starfish-protocol"
import { encodeLinkFragment, decodeLinkFragment } from "@drakkar.software/starfish-protocol"

import type { Space, SealedBlob, CapMap, PubAccessMap } from "./config.js"
import type { Session } from "./session.js"
import {
  hydrateSpaceAccessStore,
  localSpaceAccessEntries,
  saveSpaceAccessEntry,
} from "./space-access-store.js"
import type { LinkAccessPayload } from "./space-access-store.js"
import {
  assertCapForMe,
  assertCapNotExpired,
  capNonce,
  ephemeralSubject,
  evictKeyringMember,
  mintCap,
  parseJoinRequest,
} from "./invite-helpers.js"
import { signKemSig } from "./request-verify.js"
import { addSpaceKeyringRecipient, ensureSpaceKeyringRecipient, isKeyringMissing } from "./client.js"
import {
  addJoinedSpaceWithCap,
  addJoinedSpaceWithLinkAccess,
  addSpaceMember,
  buildSpace,
  readSpaces,
  updateSpacesDoc,
  removeSpaceMember,
} from "./registry.js"
import { sealToSelf, unsealFromSelf } from "./account-seal.js"
import { createComposedStore } from "./keyed-store.js"
import type { JoinRequest, SpaceInviteLinkToken } from "./token-types.js"

// ── recipientFor helper ────────────────────────────────────────────────────────

import { RECIPIENT_LABEL_LEN } from "./layout.js"

function recipientFor(subKem: string, userId: string) {
  return { subKem, userId, label: userId.slice(0, RECIPIENT_LABEL_LEN) }
}

// ── JoinRequest export ────────────────────────────────────────────────────────

export type { JoinRequest }

export function makeJoinRequest(session: Session): string {
  const kemSig = signKemSig(session.keys)
  const req: JoinRequest = {
    edPub: session.keys.edPub,
    kemPub: session.keys.kemPub,
    userId: session.userId,
    kemSig,
  }
  return JSON.stringify(req)
}

// ── Space invite store (nonces for full eviction) ─────────────────────────────

export interface StoredSpaceInvite {
  edPub: string
  kemPub: string
  /** Retained cap nonce + expiry for the space member cap (`spaceMemberScope`). */
  cap: { nonce: string; exp: number }
}

// Keyed `${spaceId}:${userId}` → invite.
const _spaceInviteStore = createComposedStore<StoredSpaceInvite, [string, string]>(
  (spaceId, userId) => `${spaceId}:${userId}`,
)

const _siRaw = _spaceInviteStore.store

/** Save an invite entry for future revocation. */
export const saveSpaceInviteEntry = (spaceId: string, userId: string, entry: StoredSpaceInvite): void =>
  _spaceInviteStore.for(spaceId, userId).set(entry)
/** Retrieve a stored invite entry. Returns null when absent. */
export const getSpaceInviteEntry = (spaceId: string, userId: string): StoredSpaceInvite | null =>
  _spaceInviteStore.for(spaceId, userId).get() ?? null
/** Clear all entries (e.g. on sign-out). */
export const clearSpaceInviteStore = (): void => {
  const raw = _siRaw.serialize()
  if (raw === "{}") return
  // Bulk-clear by re-hydrating a blank store snapshot.
  const keys = Object.keys(JSON.parse(raw) as Record<string, unknown>)
  for (const k of keys) _siRaw.clear(k)
}
/** Snapshot the store for persistence across reloads. */
export const serializeSpaceInviteStore = (): string => _siRaw.serialize()
/** Restore the store after a reload (additive — does not clear existing entries). */
export const hydrateSpaceInviteStore = (raw: string): void => _siRaw.hydrate(raw)

interface SpaceInvite {
  spaceId: string
  spaceName: string
  cap: unknown
}

/**
 * Owner: invite an identity into a space. Records them in the roster, mints a
 * space-scoped member cap, and adds them to the space-wide keyring if it exists.
 * Returns the invite bundle JSON.
 */
export async function inviteToSpace(
  session: Session,
  spaceId: string,
  requestJson: string,
  canWrite = true,
  spaceName?: string,
): Promise<string> {
  const req = await parseJoinRequest(requestJson, "That is not a valid join request", session)
  await addSpaceMember(session.accountClient, spaceId, session.userId, req.userId, session)

  // Ensure the space-wide keyring exists, then add the invitee as a recipient.
  await ensureSpaceKeyringRecipient(session, spaceId, recipientFor(req.kemPub, req.userId))

  const cap = await mintCap(
    session,
    { edPubHex: req.edPub, kemPubHex: req.kemPub, userIdHex: req.userId },
    "content",
    session.layout.spaceMemberScope(spaceId, canWrite),
  )
  const nonce = capNonce(cap)
  if (nonce) saveSpaceInviteEntry(spaceId, req.userId, { edPub: req.edPub, kemPub: req.kemPub, cap: nonce })

  let name = spaceName?.trim()
  if (!name) {
    const { spaces } = await readSpaces(session.accountClient, session)
    name = spaces.find((s) => s.id === spaceId)?.name ?? "Space"
  }
  const invite: SpaceInvite = { spaceId, spaceName: name, cap }
  return JSON.stringify(invite)
}

/**
 * Invitee: accept a space invite — store the cap and register the space.
 * Returns the joined space.
 */
export async function acceptSpaceInvite(session: Session, inviteJson: string): Promise<Space> {
  const inv = JSON.parse(inviteJson) as Partial<SpaceInvite>
  const cap = inv.cap as { kind?: string; sub?: string } | undefined
  if (!cap || !inv.spaceId) throw new Error("That is not a valid space invite.")
  assertCapForMe(cap, session.keys.edPub, "That is not a valid space invite.", "This invite was issued for a different identity.")
  const spaceId = inv.spaceId
  const capJson = JSON.stringify(cap)
  const space = buildSpace(spaceId, inv.spaceName ?? "")
  await addJoinedSpaceWithCap(session.accountClient, session, space, capJson)
  saveSpaceAccessEntry(spaceId, { kind: "member", cap: capJson })
  return space
}

// ── Link-based joins ──────────────────────────────────────────────────────────

export type { SpaceInviteLinkToken }

export function encodeSpaceInviteLink(origin: string, token: SpaceInviteLinkToken): string {
  return encodeLinkFragment(origin, "join", token)
}

export function decodeSpaceInviteLink(fragment: string): SpaceInviteLinkToken {
  const raw = decodeLinkFragment<{ spaceId: string; cap: unknown; key: string } & Partial<SpaceInviteLinkToken>>(
    fragment,
    (tok: unknown) => {
      const t = tok as Record<string, unknown>
      return !!t && typeof t.spaceId === "string" && !!t.cap && typeof t.key === "string"
        ? (t as { spaceId: string; cap: unknown; key: string } & Partial<SpaceInviteLinkToken>)
        : null
    },
    "That space invite link is malformed or incomplete.",
  )
  return {
    v: 1,
    spaceId: raw.spaceId,
    spaceName: raw.spaceName ?? "Space",
    cap: raw.cap,
    key: raw.key,
    kemPriv: raw.kemPriv,
    kemPub: raw.kemPub,
    write: !!raw.write,
  }
}

/**
 * Owner: create a shareable invite link for a PUBLIC space.
 *
 * The link is a BEARER token — anyone who holds it can join. Bound the exposure
 * with `opts.ttlSec` / `opts.expiresAt` (the cap's server-enforced `exp`; default
 * 30 days when omitted). The returned `inviteUserId` is the ephemeral member's
 * userId — pass it to `revokeSpaceAccess(session, spaceId, inviteUserId, …)` to
 * kill this one link without affecting other members or links.
 *
 * Bearer links are inherently multi-use: there is no client-only single-use, as
 * the secret lives entirely in the URL fragment and the server counts no
 * redemptions. Use a short TTL and/or revoke after the intended join.
 */
export async function createSpaceInviteLink(
  session: Session,
  spaceId: string,
  spaceName: string,
  write: boolean,
  origin: string,
  opts: { ttlSec?: number; nbf?: number; expiresAt?: number } = {},
): Promise<{ token: SpaceInviteLinkToken; link: string; inviteUserId: string }> {
  const { ek, userId: ephemeralUserId, subject } = await ephemeralSubject(session)
  const capOpts = { ttlSec: opts.ttlSec, nbf: opts.nbf, expiresAt: opts.expiresAt }
  const cap = await mintCap(session, subject, "content", session.layout.spaceMemberScope(spaceId, write), capOpts)
  const nonce = capNonce(cap)
  if (nonce) saveSpaceInviteEntry(spaceId, ephemeralUserId, { edPub: ek.edPub, kemPub: ek.kemPub, cap: nonce })
  // Add the ephemeral userId to the roster
  await addSpaceMember(session.accountClient, spaceId, session.userId, ephemeralUserId, session)

  // Ensure the keyring exists, then add the ephemeral KEM so link-bearers can decrypt enc content.
  await ensureSpaceKeyringRecipient(session, spaceId, recipientFor(ek.kemPub, ephemeralUserId))

  const token: SpaceInviteLinkToken = {
    v: 1, spaceId, spaceName, cap, key: ek.edPriv, kemPriv: ek.kemPriv, kemPub: ek.kemPub, write,
  }
  return { token, link: encodeSpaceInviteLink(origin, token), inviteUserId: ephemeralUserId }
}

/**
 * Any user: join a space by redeeming an invite link token.
 */
export async function joinSpaceByLink(session: Session, token: SpaceInviteLinkToken): Promise<Space> {
  assertCapNotExpired(token.cap, "That space invite link is no longer usable")
  const space = buildSpace(token.spaceId, token.spaceName)
  const accessPayload = { cap: token.cap, key: token.key, kemPriv: token.kemPriv, kemPub: token.kemPub, write: token.write }
  const sealed = await sealToSelf(session, JSON.stringify(accessPayload))
  await addJoinedSpaceWithLinkAccess(session.accountClient, session, space, sealed)
  saveSpaceAccessEntry(token.spaceId, {
    kind: "link", cap: token.cap, key: token.key, kemPriv: token.kemPriv, kemPub: token.kemPub, write: token.write,
  })
  return space
}

/**
 * Add a device's KEM key as a recipient of a space's keyring.
 * Call this after device pairing.
 */
export async function addDeviceToSpaceKeyring(
  session: Session,
  spaceId: string,
  device: { kemPub: string; edPub: string; userId: string },
): Promise<void> {
  try {
    await addSpaceKeyringRecipient(session, spaceId, recipientFor(device.kemPub, device.userId))
  } catch (err) {
    if (!isKeyringMissing(err)) throw err
  }
}

/**
 * Single sign-in hydration: merges server-side caps and sealed link access
 * into the unified space-access store. Call once on sign-in / account switch.
 */
export async function recoverSpaceAccess(
  session: Session,
  server: { caps: Record<string, string>; pubAccess: Record<string, SealedBlob> },
): Promise<void> {
  // Unseal link access blobs
  const linkAccess: Record<string, LinkAccessPayload> = {}
  for (const [spaceId, sealed] of Object.entries(server.pubAccess)) {
    try {
      const raw = await unsealFromSelf(session, sealed)
      const parsed = JSON.parse(raw) as LinkAccessPayload
      if (parsed.cap && parsed.key) linkAccess[spaceId] = parsed
    } catch (e) {
      console.error("[starfish-spaces] recoverSpaceAccess: failed to unseal", spaceId, (e instanceof Error ? e.message : String(e)))
    }
  }

  await hydrateSpaceAccessStore(session.userId, server.caps, linkAccess)

  // Backfill local-only entries to the server
  const local = localSpaceAccessEntries()
  const missingMemberCaps = Object.entries(local)
    .filter(([id, e]) => e.kind === "member" && !(id in server.caps))
  const missingLinks = Object.entries(local)
    .filter(([id, e]) => e.kind === "link" && !(id in server.pubAccess))

  if (missingMemberCaps.length === 0 && missingLinks.length === 0) return

  try {
    const newCaps: CapMap = {}
    for (const [id, e] of missingMemberCaps) if (e.kind === "member") newCaps[id] = e.cap

    const newPubAccess: PubAccessMap = {}
    for (const [id, e] of missingLinks) {
      if (e.kind === "link") {
        newPubAccess[id] = await sealToSelf(
          session,
          JSON.stringify({ cap: e.cap, key: e.key, kemPriv: e.kemPriv, kemPub: e.kemPub, write: e.write }),
        )
      }
    }

    await updateSpacesDoc(session.accountClient, session, (cur) => ({
      spaces: cur.spaces,
      caps: { ...cur.caps, ...newCaps },
      pubAccess: { ...cur.pubAccess, ...newPubAccess },
    }))
  } catch (e) {
    console.error("[starfish-spaces] recoverSpaceAccess: backfill failed", (e instanceof Error ? e.message : String(e)))
  }
}

// ── Space-tier full eviction ──────────────────────────────────────────────────

/**
 * Fully evict a space member — rotates keyring AND submits revocation.
 */
export async function revokeSpaceAccess(
  session: Session,
  spaceId: string,
  userId: string,
  opts: {
    generation: number
    priorRevoked?: RevocationEntry[]
    submitRevocation: (list: RevocationList) => Promise<void>
  },
): Promise<{ revoked: boolean }> {
  const invite = getSpaceInviteEntry(spaceId, userId)
  if (!invite) {
    throw new Error(
      `revokeSpaceAccess: no stored invite for ${userId} on space ${spaceId} — call saveSpaceInviteEntry or use inviteToSpace / createSpaceInviteLink (which auto-store the entry)`,
    )
  }

  await evictKeyringMember(
    session.contentClient,
    session,
    session.layout.keyringName(spaceId),
    { sub: invite.edPub, nonce: invite.cap.nonce, exp: invite.cap.exp, subKem: invite.kemPub },
    { generation: opts.generation, priorRevoked: opts.priorRevoked, submitRevocation: opts.submitRevocation },
  )

  await removeSpaceMember(session.accountClient, spaceId, userId, session)

  return { revoked: true }
}
