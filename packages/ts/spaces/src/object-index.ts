/**
 * Headless reads + create-time seeding of a space's unified OBJECT INDEX.
 *
 * The index at `spaces/{spaceId}/objects/_index` is always PLAINTEXT (member-gated).
 * For `invite` nodes the title/emoji are stripped before storage so non-invited
 * members see only the structural fields (id, type, parentId, order, access, enc).
 * Invited members read the real title from the node's content doc.
 *
 * Encryption lives at the node content level, not here.
 */
import type { ObjectNode } from "./config.js"
import type { Session } from "./session.js"
import { getSpaceClient } from "./space-access.js"
import { runCas } from "./cas-retry.js"
import { getCachedDoc, noteDoc } from "./doc-cache.js"

/** Extract the `objects` array from a raw index doc body, or `[]` when absent/invalid. */
function readIndexObjects(raw: unknown): ObjectNode[] {
  const objects = (raw as { objects?: unknown })?.objects
  return Array.isArray(objects) ? (objects as ObjectNode[]) : []
}

/** Strip title/emoji from invite nodes before writing to the index. */
function serializeForIndex(node: ObjectNode): ObjectNode {
  if (node.access === "invite") {
    const { emoji: _e, ...rest } = node
    return { ...rest, title: "" }
  }
  return node
}

/** The index doc body sent on push (invite nodes stripped). */
function buildIndexPayload(nodes: ObjectNode[]): { v: 2; objects: ObjectNode[]; updatedAt: number } {
  return { v: 2, objects: nodes.map(serializeForIndex), updatedAt: Date.now() }
}

/**
 * Write the create-time seed into a space's index doc.
 * Idempotent: a no-op if the index doc already exists.
 * Pass `nodes` to seed with initial objects; defaults to an empty index.
 */
export async function pushIndexSeed(
  client: import("@drakkar.software/starfish-client").StarfishClient,
  spaceId: string,
  session: Session,
  nodes: ObjectNode[] = [],
): Promise<void> {
  const pullPath = session.layout.objIndexPull(spaceId)
  const pushPath = session.layout.objIndexPush(spaceId)
  const res = await client.pull(pullPath).catch(() => null)
  const existing = res?.data as Record<string, unknown> | undefined
  if (Array.isArray(existing?.objects)) return
  // Fall back to the persistent cache when the pull returns a degraded hash:"".
  // Without this, a space-creation push with baseHash:"" would 409 if the index
  // doc exists but the server returns a corrupt envelope (hash:"").
  let baseHash = res?.hash || getCachedDoc(pushPath)?.hash || ""
  if (!baseHash) {
    const peeked = await client.peekCache(pullPath).catch(() => null)
    if (peeked?.hash) baseHash = peeked.hash
  }
  await client.push(pushPath, buildIndexPayload(nodes), baseHash)
}

/**
 * Seed a brand-new space's index as the OWNER. Always plaintext.
 * Pass `nodes` to seed with initial objects; defaults to an empty index.
 */
export async function seedSpaceObjectIndex(
  session: Session,
  spaceId: string,
  nodes: ObjectNode[] = [],
): Promise<void> {
  const client = getSpaceClient(spaceId, session)
  await pushIndexSeed(client, spaceId, session, nodes)
}

/**
 * Headless read-modify-write of a space's unified OBJECT INDEX.
 * Always plaintext. Retries up to 3 times on ConflictError.
 *
 * The mutator receives the current nodes with real (or empty, for invite) titles.
 * Before writing back, invite nodes have their title/emoji stripped again.
 */
export async function updateObjectIndex(
  session: Session,
  spaceId: string,
  mutator: (nodes: ObjectNode[], now: number) => ObjectNode[] | null,
): Promise<void> {
  const client = getSpaceClient(spaceId, session)
  const pullPath = session.layout.objIndexPull(spaceId)
  const pushPath = session.layout.objIndexPush(spaceId)
  await runCas(async ({ currentHash }) => {
    let cached = getCachedDoc(pushPath)
    // Cold in-memory cache (e.g. after a tab reload): seed data+hash from the
    // persistent read-through cache so we can skip the pull. The index is plaintext
    // so caching both data and hash is safe. Returns null when no cache backend is
    // configured or on a miss → falls through to the existing pull path.
    if (!cached?.data && !currentHash) {
      const peeked = await client.peekCache(pullPath).catch(() => null)
      if (peeked?.hash && peeked.data) {
        noteDoc(pullPath, peeked.hash, peeked.data as Record<string, unknown>)
        cached = getCachedDoc(pushPath)
      }
    }
    let baseHash: string
    let cur: ObjectNode[]
    if (cached?.data && !currentHash) {
      // Warm cache, not a 409 retry: reuse cached data + hash — no pull.
      baseHash = cached.hash
      cur = readIndexObjects(cached.data)
    } else {
      // Cold cache OR 409 retry: pull fresh for data + authoritative hash.
      const res = await client.pull(pullPath)
      // Never push "" once we have a known good hash in the cache.
      baseHash = res?.hash || currentHash || cached?.hash || ""
      cur = readIndexObjects(res?.data)
      if (res?.hash) noteDoc(pullPath, res.hash, res.data as Record<string, unknown>)
    }
    const next = mutator(cur, Date.now())
    if (next === null) return
    const payload = buildIndexPayload(next)
    const pushRes = await client.push(pushPath, payload, baseHash)
    noteDoc(pushPath, pushRes.hash, payload)
  })
}

/**
 * Read the current object tree (read-only, no mutation). Returns the stored
 * nodes (titles are empty for invite nodes the caller is not invited to).
 */
export async function readObjectTree(
  session: Session,
  spaceId: string,
): Promise<ObjectNode[]> {
  const client = getSpaceClient(spaceId, session)
  const res = await client.pull(session.layout.objIndexPull(spaceId)).catch(() => null)
  return readIndexObjects(res?.data)
}
