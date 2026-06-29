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
  const res = await client.pull(session.layout.objIndexPull(spaceId)).catch(() => null)
  const existing = res?.data as Record<string, unknown> | undefined
  if (Array.isArray(existing?.objects)) return
  await client.push(session.layout.objIndexPush(spaceId), buildIndexPayload(nodes), res?.hash ?? "")
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
  await runCas(async () => {
    const res = await client.pull(session.layout.objIndexPull(spaceId))
    if (res.hash === "") {
      // Temporary diagnostic: empty hash means the stored doc is missing or hash-less.
      // Sending "" triggers the server's heal path (else: "" != "" → accept).
      console.warn("[objindex] empty hash on _index — healing", spaceId)
    }
    const cur = readIndexObjects(res?.data)
    const next = mutator(cur, Date.now())
    if (next === null) return
    await client.push(session.layout.objIndexPush(spaceId), buildIndexPayload(next), res?.hash ?? "")
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
