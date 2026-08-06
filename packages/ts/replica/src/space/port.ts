/**
 * The ONLY file under `./space` that imports `@drakkar.software/starfish-spaces`.
 * `SpaceMirrorChannel` (./mirror-channel.ts) and `readSpaceMirror` (./reader.ts)
 * depend on `SpacePort`, not on `starfish-spaces` directly — so they stay
 * unit-testable with a fake Map-backed port (no `vi.mock`, matching this
 * monorepo's fake-client idiom — see `packages/ts/sharing/tests/evict.test.ts`)
 * and, more importantly, so `../channel.js`/`../manager.js` never end up
 * pulling `starfish-spaces` into a bundle that doesn't use this subpath.
 */
import {
  createNode as sfCreateNode,
  createSpace as sfCreateSpace,
  getNodeAccess as sfGetNodeAccess,
  readObjectTree as sfReadObjectTree,
  readSpaces as sfReadSpaces,
  type CreateNodeInput,
  type NodeAccess,
  type NodeAccessHandle,
  type Session,
} from "@drakkar.software/starfish-spaces"

export type { CreateNodeInput, NodeAccess, NodeAccessHandle, Session }

/** The subset of `starfish-spaces`' space/node API `SpaceMirrorChannel` needs. */
export interface SpacePort {
  readSpaces(session: Session): Promise<{ spaces: { id: string; name: string }[] }>
  createSpace(session: Session, name: string): Promise<{ id: string; name: string }>
  readObjectTree(session: Session, spaceId: string): Promise<{ id: string; type: string }[]>
  createNode(session: Session, spaceId: string, input: CreateNodeInput): Promise<{ id: string }>
  getNodeAccess(
    spaceId: string,
    nodeId: string,
    node: { access?: NodeAccess; enc?: boolean },
    session: Session,
  ): Promise<NodeAccessHandle>
}

/** The real `SpacePort`, bound to `@drakkar.software/starfish-spaces`. */
export const defaultSpacePort: SpacePort = {
  readSpaces: (session) => sfReadSpaces(session.accountClient, session),
  createSpace: sfCreateSpace,
  readObjectTree: sfReadObjectTree,
  createNode: sfCreateNode,
  getNodeAccess: (spaceId, nodeId, node, session) => sfGetNodeAccess(spaceId, nodeId, node, session),
}

/** In-flight find-or-create calls, keyed by `${userId}:${name}`, so two
 *  concurrent callers racing on the same (session, name) coalesce into one
 *  actual read+create instead of each independently missing the not-yet-
 *  created space and both calling `createSpace`. This only protects against
 *  in-process concurrency (e.g. a scheduled sync and an interactive action
 *  overlapping in the same app session) — it cannot prevent two different
 *  devices from racing the same identity's space registry, which would need
 *  server-side idempotent creation. */
const _inFlightFindOrCreate = new Map<string, Promise<{ id: string; name: string }>>()

/**
 * Find one of the session's spaces by name, creating it on first use.
 * TOFU-first-writer semantics apply exactly like every other starfish-spaces
 * space (see `spaceregistry`'s server-side role enricher) — the caller is
 * always this identity's own device, so it's always the legitimate owner on
 * first creation.
 */
export async function findOrCreateSpace(
  session: Session,
  name: string,
  port: SpacePort = defaultSpacePort,
): Promise<{ id: string; name: string }> {
  const key = `${session.userId}:${name}`
  const inFlight = _inFlightFindOrCreate.get(key)
  if (inFlight) return inFlight

  const promise = (async () => {
    const doc = await port.readSpaces(session)
    const existing = doc.spaces.find((space) => space.name === name)
    if (existing) return existing
    return port.createSpace(session, name)
  })()

  _inFlightFindOrCreate.set(key, promise)
  try {
    return await promise
  } finally {
    _inFlightFindOrCreate.delete(key)
  }
}
