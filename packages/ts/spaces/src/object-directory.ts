/**
 * Client-side reader for the global public-object directory.
 *
 * The directory is a server-maintained projection doc at
 * `_index/objects/{shard}` (collection `objectindex`, `readRoles:["public"]`,
 * `pullOnly`). It is populated by the `starfish-projection` plugin from
 * `objindex` writes. Any node with `access:'public'` across any space appears here.
 *
 * Wire-up: call `readObjectDirectory()` (no auth required — world-readable).
 * Returns a flat array; each entry carries its owning `spaceId` so the caller
 * can navigate into the space or deep-link directly to the object.
 */

import { makeAnonSpaceClient } from "./client.js"
import type { Session } from "./session.js"

/**
 * A single public object entry in the global directory.
 */
export interface ObjectDirectoryEntry {
  /** The space this node belongs to. */
  spaceId: string
  id: string
  title: string
  type: string
  emoji?: string
  updatedAt: number
}

/** Internal shape of one per-space bucket in the directory doc. */
interface SpaceBucket {
  nodes?: unknown[]
}

/**
 * Parse the raw directory doc body into a flat `ObjectDirectoryEntry[]`.
 *
 * Pure function — directly unit-testable without network mocks. Exported so
 * callers (e.g. cached or pre-fetched data) can use it independently.
 */
export function parseObjectDirectoryDoc(data: unknown): ObjectDirectoryEntry[] {
  if (!data || typeof data !== "object" || Array.isArray(data)) return []
  const map = data as Record<string, SpaceBucket>
  const entries: ObjectDirectoryEntry[] = []
  for (const [spaceId, bucket] of Object.entries(map)) {
    if (!bucket || !Array.isArray(bucket.nodes)) continue
    for (const n of bucket.nodes) {
      if (!n || typeof n !== "object") continue
      const node = n as Record<string, unknown>
      const entry: ObjectDirectoryEntry = {
        spaceId,
        id: String(node.id ?? ""),
        title: typeof node.title === "string" ? node.title : "",
        type: typeof node.type === "string" ? node.type : "page",
        updatedAt: typeof node.updatedAt === "number" ? node.updatedAt : 0,
      }
      if (typeof node.emoji === "string") entry.emoji = node.emoji
      entries.push(entry)
    }
  }
  return entries
}

/**
 * Pull the global public-object directory and return a flat entry list.
 *
 * No authentication required — the directory collection is world-readable.
 * Returns an empty array on network error or an empty/malformed directory.
 *
 * @param session The current session (provides baseUrl, namespace, and layout).
 * @param shard   Directory shard key (default `'public'`).
 */
export async function readObjectDirectory(
  session: Session,
  shard: string = "public",
): Promise<ObjectDirectoryEntry[]> {
  const client = makeAnonSpaceClient({ baseUrl: session.baseUrl, namespace: session.namespace })
  let res: { data?: unknown } | null = null
  try {
    res = await client.pull(session.layout.objectDirPull(shard))
  } catch {
    return []
  }
  return parseObjectDirectoryDoc(res?.data)
}
