/**
 * Space registries (plaintext metadata docs). A user's spaces live at
 * `user/{userId}/_spaces`; each space's ACCESS RECORD (owner/members + shared
 * name/image) at `spaces/{spaceId}/_access`. The object tree lives in the plaintext
 * unified object index (`objects/_index`, see `object-index.ts`); `_access` is the
 * owner-only access record. Spaces are neutral containers — visibility and encryption
 * are per-node properties (see `ObjectNode.access` / `ObjectNode.enc`).
 */
import { StarfishHttpError } from "@drakkar.software/starfish-client"
import type { StarfishClient } from "@drakkar.software/starfish-client"

import type { CapMap, PubAccessMap, Space } from "./config.js"
import type { SealedBlob } from "./config.js"
import { randomId } from "@drakkar.software/starfish-protocol"
import type { Session } from "./session.js"
import { seedSpaceObjectIndex } from "./object-index.js"
import { runCas } from "./cas-retry.js"

/** Owner-set, SHARED space identity, persisted in the `_access` registry doc
 *  (plaintext — NOT E2EE). `image` is a data URI. All fields optional for back-compat. */
export interface SpaceMeta {
  name?: string | null
  image?: string | null
}

/** A resolved name/image update fanned out so providers adopts a
 *  freshly-reconciled value without waiting for its next navigation refresh. */
export interface SpaceMetaUpdate {
  name: string
  short: string
  image?: string
}

const SPACE_SHORT_LENGTH = 2
const SPACE_FALLBACK_SUFFIX = 6

/** Build a Space object from id + name with computed `short` monogram. */
export function buildSpace(id: string, name: string, overrides?: Partial<Space>): Space {
  const trimmed = name.trim() || `space-${id.slice(-SPACE_FALLBACK_SUFFIX)}`
  return {
    id,
    name: trimmed,
    members: 1,
    ...overrides,
  }
}

const spaceMetaListeners = new Set<(spaceId: string, meta: SpaceMetaUpdate) => void>()

export function onSpaceMeta(fn: (spaceId: string, meta: SpaceMetaUpdate) => void): () => void {
  spaceMetaListeners.add(fn)
  return () => {
    spaceMetaListeners.delete(fn)
  }
}

export function broadcastSpaceMeta(spaceId: string, meta: SpaceMetaUpdate): void {
  for (const fn of spaceMetaListeners) fn(spaceId, meta)
}

export interface SpacesDoc {
  spaces: Space[]
  caps: CapMap
  pubAccess: PubAccessMap
  /** App-specific registry fields the SDK does not model. Round-tripped untouched on
   *  every CAS write so a generic-SDK mutation never drops a consumer's own data. */
  extra: Record<string, unknown>
  hash: string | null
}

/** The `_spaces` doc body sent on push — the modelled core fields plus any app-specific
 *  fields spread at the top level (never a nested `extra` key). */
type SpacesPayload = {
  spaces: Space[]
  caps: CapMap
  pubAccess: PubAccessMap
  [key: string]: unknown
}

/** Core keys the SDK models explicitly; everything else in the doc body lives in `extra`.
 *  `v` is the protocol version (re-added on write); `hash` is the CAS token (never in body). */
const CORE_SPACES_KEYS = new Set(["spaces", "caps", "pubAccess", "v", "hash"])

/** Build the `_spaces` doc body: app-specific `extra` fields spread FIRST so the modelled
 *  core fields always take precedence. No nested `extra` key reaches storage. */
function toPayload(doc: SpacesDoc): SpacesPayload {
  return {
    ...doc.extra,
    spaces: doc.spaces,
    caps: doc.caps,
    pubAccess: doc.pubAccess,
  }
}

/** Collect every doc-body key the SDK does not model into `extra`. */
function collectExtra(data: Record<string, unknown> | undefined): Record<string, unknown> {
  if (!data || typeof data !== "object") return {}
  const extra: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(data)) if (!CORE_SPACES_KEYS.has(k)) extra[k] = v
  return extra
}

/** Coerce a raw `_spaces` doc body (or `undefined`) into a typed {@link SpacesDoc}. */
function coerceSpacesDoc(data: Record<string, unknown> | undefined, hash: string | null): SpacesDoc {
  const raw = data as { spaces?: Space[]; caps?: CapMap; pubAccess?: PubAccessMap } | undefined
  return {
    spaces: Array.isArray(raw?.spaces) ? raw!.spaces! : [],
    caps: raw?.caps && typeof raw.caps === "object" ? raw.caps : {},
    pubAccess: raw?.pubAccess && typeof raw.pubAccess === "object" ? raw.pubAccess : {},
    extra: collectExtra(data),
    hash,
  }
}

async function pullSpacesDoc(client: StarfishClient, session: Session): Promise<SpacesDoc> {
  const res = await client.pull(session.layout.spacesPull(session.userId)).catch((err: unknown) => {
    if (err instanceof StarfishHttpError && err.status === 404) return null
    throw err
  })
  return coerceSpacesDoc(res?.data as Record<string, unknown> | undefined, res?.hash ?? null)
}

export async function readSpaces(client: StarfishClient, session: Session): Promise<SpacesDoc> {
  try {
    return await pullSpacesDoc(client, session)
  } catch (err) {
    console.error("[readSpaces] failed to pull spaces registry", err)
    return coerceSpacesDoc(undefined, null)
  }
}

export function updateSpacesDoc(
  client: StarfishClient,
  session: Session,
  mutator: (cur: { spaces: Space[]; caps: CapMap; pubAccess: PubAccessMap }) => { spaces: Space[]; caps: CapMap; pubAccess: PubAccessMap },
): Promise<void> {
  return runCas(async () => {
    const doc = await pullSpacesDoc(client, session)
    const cur = { spaces: doc.spaces, caps: doc.caps, pubAccess: doc.pubAccess }
    const next = mutator(cur)
    if (next === cur) return
    await client.push(session.layout.spacesPush(session.userId), { v: 1 as const, ...toPayload({ ...doc, ...next }), }, doc.hash)
  })
}

/**
 * Read-modify-CAS-write ONE app-specific (`extra`) field of the `_spaces` doc.
 */
export function updateSpacesExtraField<T>(
  client: StarfishClient,
  session: Session,
  key: string,
  mutator: (cur: T | undefined) => T | null,
): Promise<void> {
  return runCas(async () => {
    const doc = await pullSpacesDoc(client, session)
    const next = mutator(doc.extra[key] as T | undefined)
    if (next === null) return
    const payload = { ...toPayload(doc), [key]: next }
    await client.push(session.layout.spacesPush(session.userId), { v: 1 as const, ...payload }, doc.hash)
  })
}

export async function writeSpaces(
  client: StarfishClient,
  session: Session,
  spaces: Space[],
): Promise<void> {
  await updateSpacesDoc(client, session, (cur) => ({ spaces, caps: cur.caps, pubAccess: cur.pubAccess }))
}

export async function reorderSpaces(client: StarfishClient, session: Session, order: string[]): Promise<void> {
  await updateSpacesDoc(client, session, (cur) => {
    const byId = new Map(cur.spaces.map((s) => [s.id, s]))
    const next: Space[] = []
    for (const id of order) {
      const s = byId.get(id)
      if (s) {
        next.push(s)
        byId.delete(id)
      }
    }
    for (const s of cur.spaces) if (byId.has(s.id)) next.push(s)
    const unchanged = next.length === cur.spaces.length && next.every((s, i) => s === cur.spaces[i])
    if (unchanged) return cur
    return { spaces: next, caps: cur.caps, pubAccess: cur.pubAccess }
  })
}

export type SpaceEntry = {
  owner: string | null
  members: string[]
  name: string | null
  image: string | null
  hash: string | null
}

export async function readSpaceAccess(
  client: StarfishClient,
  spaceId: string,
  session: Session,
): Promise<SpaceEntry> {
  const res = await client.pull(session.layout.spaceAccessPull(spaceId)).catch((err: unknown) => {
    if (err instanceof StarfishHttpError && err.status === 404) return null
    throw err
  })
  const data = res?.data as { owner?: string; members?: unknown[]; name?: string; image?: string } | undefined
  return {
    owner: typeof data?.owner === "string" ? data.owner : null,
    members: Array.isArray(data?.members)
      ? data!.members!.filter((m): m is string => typeof m === "string")
      : [],
    name: typeof data?.name === "string" ? data.name : null,
    image: typeof data?.image === "string" ? data.image : null,
    hash: res?.hash ?? null,
  }
}

export async function writeSpaceAccess(
  client: StarfishClient,
  spaceId: string,
  owner: string,
  members: string[],
  hash: string | null,
  session: Session,
  meta?: SpaceMeta,
): Promise<void> {
  const name = meta?.name?.trim() || undefined
  const image = meta?.image || undefined
  await client.push(
    session.layout.spaceAccessPush(spaceId),
    {
      v: 1, owner, members,
      ...(name ? { name } : {}),
      ...(image ? { image } : {}),
    },
    hash,
  )
}

export async function addSpaceMember(
  client: StarfishClient,
  spaceId: string,
  ownerUserId: string,
  memberUserId: string,
  session: Session,
): Promise<void> {
  const { owner, members, name, image, hash } = await readSpaceAccess(client, spaceId, session)
  if (memberUserId === (owner ?? ownerUserId) || members.includes(memberUserId)) return
  await writeSpaceAccess(client, spaceId, owner ?? ownerUserId, [...members, memberUserId], hash, session, { name, image })
}

/** Remove a member from the space roster (used for link revocation). */
export async function removeSpaceMember(
  client: StarfishClient,
  spaceId: string,
  memberUserId: string,
  session: Session,
): Promise<void> {
  const { owner, members, name, image, hash } = await readSpaceAccess(client, spaceId, session)
  if (!members.includes(memberUserId)) return
  await writeSpaceAccess(
    client,
    spaceId,
    owner ?? memberUserId,
    members.filter((m) => m !== memberUserId),
    hash,
    session,
    { name, image },
  )
}

/** Invitee/owner-side: drop a space from the identity's own list + forget its cap
 *  and link-access credential. Idempotent (no-op when absent). */
export async function removeJoinedSpace(client: StarfishClient, session: Session, spaceId: string): Promise<void> {
  await updateSpacesDoc(client, session, (cur) => {
    if (!cur.spaces.some((s) => s.id === spaceId)) return cur
    const caps = { ...cur.caps }
    delete caps[spaceId]
    const pubAccess = { ...cur.pubAccess }
    delete pubAccess[spaceId]
    return { spaces: cur.spaces.filter((s) => s.id !== spaceId), caps, pubAccess }
  })
}

/** Move one space to an absolute index in the list (clamped). */
export async function moveSpace(client: StarfishClient, session: Session, spaceId: string, toIndex: number): Promise<void> {
  await updateSpacesDoc(client, session, (cur) => {
    const from = cur.spaces.findIndex((s) => s.id === spaceId)
    if (from === -1) return cur
    const next = [...cur.spaces]
    const [moved] = next.splice(from, 1)
    next.splice(Math.max(0, Math.min(toIndex, next.length)), 0, moved)
    if (next.every((s, i) => s === cur.spaces[i])) return cur
    return { spaces: next, caps: cur.caps, pubAccess: cur.pubAccess }
  })
}

/** Append a space to the joined list (dup-guarded) plus optional cap / link-access updates. */
function addSpaceWithUpdates(
  client: StarfishClient,
  session: Session,
  space: Space,
  updates?: { caps?: CapMap; pubAccess?: PubAccessMap },
): Promise<void> {
  return updateSpacesDoc(client, session, (cur) => {
    const exists = cur.spaces.some((s) => s.id === space.id)
    if (exists && !updates) return cur
    return {
      spaces: exists ? cur.spaces : [...cur.spaces, space],
      caps: updates?.caps ? { ...cur.caps, ...updates.caps } : cur.caps,
      pubAccess: updates?.pubAccess ? { ...cur.pubAccess, ...updates.pubAccess } : cur.pubAccess,
    }
  })
}

export function addJoinedSpace(client: StarfishClient, session: Session, space: Space): Promise<void> {
  return addSpaceWithUpdates(client, session, space)
}

export function addJoinedSpaceWithCap(client: StarfishClient, session: Session, space: Space, capJson: string): Promise<void> {
  return addSpaceWithUpdates(client, session, space, { caps: { [space.id]: capJson } })
}

export function addJoinedSpaceWithLinkAccess(client: StarfishClient, session: Session, space: Space, sealed: SealedBlob): Promise<void> {
  return addSpaceWithUpdates(client, session, space, { pubAccess: { [space.id]: sealed } })
}

/**
 * Create a new space owned by the identity. Seeds an empty plaintext object index.
 */
export async function createSpace(
  session: Session,
  name: string,
): Promise<Space> {
  const { accountClient, userId } = session
  const { spaces } = await readSpaces(accountClient, session)
  const trimmed = name.trim() || "New Space"
  const id = `${session.spaceIdPrefix}${randomId()}`
  const space = buildSpace(id, trimmed)
  await writeSpaceAccess(accountClient, id, userId, [], null, session, { name: trimmed })
  await seedSpaceObjectIndex(session, id)
  await writeSpaces(accountClient, session, [...spaces, space])
  return space
}

export async function reconcileSpaceMeta(
  client: StarfishClient,
  session: Session,
  spaceId: string,
  shared: SpaceMeta,
  knownSpaces?: Space[],
): Promise<void> {
  const sharedName = typeof shared.name === "string" && shared.name.trim() ? shared.name : null
  const sharedImage = typeof shared.image === "string" && shared.image ? shared.image : null
  if (sharedName === null && sharedImage === null) return
  const known = knownSpaces?.find((s) => s.id === spaceId)
  if (known) {
    const name = sharedName ?? known.name
    const short = name.slice(0, 2).toUpperCase()
    const image = sharedImage ?? (known as Space & { image?: string }).image
    if (name === known.name && (image ?? null) === ((known as Space & { image?: string }).image ?? null)) return
    void short
  }
  const { spaces } = await readSpaces(client, session)
  const cur = spaces.find((s) => s.id === spaceId)
  if (!cur) return
  const name = sharedName ?? cur.name
  const image = sharedImage ?? (cur as Space & { image?: string }).image
  const short = name.slice(0, 2).toUpperCase()
  if (name === cur.name && (image ?? null) === ((cur as Space & { image?: string }).image ?? null)) return
  const next = spaces.map((s) => (s.id === spaceId ? { ...s, name, image } : s))
  await writeSpaces(client, session, next)
  broadcastSpaceMeta(spaceId, { name, short, image })
}
