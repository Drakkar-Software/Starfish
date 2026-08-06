/**
 * A `ReplicaChannel` that mirrors an app-local data source into per-collection
 * nodes of one or more Starfish spaces, encrypted under each space's own
 * keyring. This module owns the space/node mechanics — space find-or-create,
 * node find-or-create, CAS-write, clear-on-disable, and routing across
 * several spaces. What stays with the caller is the collection registry
 * (which ids exist, which space each routes to) and the `readSource`
 * callback.
 */
import type { ReplicaCallContext, ReplicaChannel } from "../channel.js"
import { planSpaceMirror, type ExistingSpaceNode } from "./plan.js"
import {
  defaultSpacePort,
  findOrCreateSpace,
  type CreateNodeInput,
  type NodeAccess,
  type Session,
  type SpacePort,
} from "./port.js"

/** One collection this channel mirrors, and which space its node lives in. */
export interface SpaceMirrorCollection {
  id: string
  spaceName: string
}

export interface SpaceMirrorResult {
  /** Space id per space name, or `null` for a space never created (nothing
   *  has ever been enabled for it) — not an error, just "nothing to report". */
  spaces: Record<string, string | null>
  created: string[]
  written: string[]
  /** Ids skipped this cycle because `changeDetection: "source-hash"` found no
   *  change since the last write. Always empty when changeDetection is "none". */
  skipped: string[]
  cleared: string[]
}

export interface SpaceMirrorChannelOptions {
  name: string
  session: Session
  /** The full collection registry this channel manages — every id/space-name
   *  pairing it will ever create, write, or clear a node for. */
  collections: readonly SpaceMirrorCollection[]
  /** Read fresh on every sync (not captured once at construction) so a
   *  settings toggle applies on the next cycle without rebuilding the channel. */
  enabledIds: () => readonly string[] | Promise<readonly string[]>
  /** Pull the CURRENT raw projection for one enabled collection from its real
   *  source. Called once per collection being written, never for one being
   *  cleared. `ctx` is threaded through unchanged from `sync()`. */
  readSource: (id: string, ctx: ReplicaCallContext) => Promise<unknown>
  /** Bare storage path for one collection's node content (no `/pull`/`/push`
   *  prefix — this channel adds that). E.g. `(spaceId, nodeId) =>
   *  \`spaces/${spaceId}/objects/mirror/${nodeId}\``. */
  docPath: (spaceId: string, nodeId: string) => string
  /** Node access/encryption mode. Default: `{ access: "space", enc: true }` —
   *  content gated by space membership, encrypted under the space's own
   *  keyring. See `starfish-spaces`' `createNode`/`getNodeAccess` docs for why
   *  `access:"invite"` is deliberately NOT the default here (it resolves
   *  through a per-node keyring nothing in a mirror-style writer ever seeds). */
  nodeEnc?: { access?: NodeAccess; enc?: boolean }
  /**
   * `"none"` (default): write every enabled collection's projection every
   * cycle, unconditionally — matches the original hand-rolled writer exactly.
   * `"source-hash"`: skip the write (for an already-existing node) when
   * `readSource`'s result is byte-identical to what this channel last wrote.
   *
   * ONLY safe when this channel is the SOLE writer of a node — a source-hash
   * skip means this channel never re-checks what's actually stored, so any
   * second writer (another device, another process) could silently diverge
   * from what a skip assumes is still there. Default "none" for that reason;
   * opt into "source-hash" only for a single-writer node.
   */
  changeDetection?: "none" | "source-hash"
  /** Override the `starfish-spaces` calls (tests). Default: the real SDK. */
  port?: SpacePort
}

const DEFAULT_NODE_ENC: { access: NodeAccess; enc: boolean } = { access: "space", enc: true }

/** Cheap content fingerprint for the optional source-hash skip — change
 *  detection, not a cryptographic digest. */
function fingerprint(data: unknown): string {
  return JSON.stringify(data ?? null)
}

export interface SpaceMirrorChannel extends ReplicaChannel {
  /** The result of the most recently completed `sync()` call. */
  readonly result: SpaceMirrorResult
}

export function createSpaceMirrorChannel(opts: SpaceMirrorChannelOptions): SpaceMirrorChannel {
  const port = opts.port ?? defaultSpacePort
  const nodeEnc: { access: NodeAccess; enc: boolean } = { ...DEFAULT_NODE_ENC, ...opts.nodeEnc }
  const changeDetection = opts.changeDetection ?? "none"
  const knownIds = new Set(opts.collections.map((c) => c.id))
  const spaceNameFor = new Map(opts.collections.map((c) => [c.id, c.spaceName]))
  const spaceNames = [...new Set(opts.collections.map((c) => c.spaceName))]
  /** nodeId -> fingerprint of the data last written to it. Only consulted
   *  under `changeDetection: "source-hash"`. */
  const lastWritten = new Map<string, string>()
  /** nodeIds already cleared by a prior cycle of THIS channel instance —
   *  skips a repeat no-op CAS write for a node that's stayed disabled since.
   *  Per-instance, not per-space-content: a fresh channel (e.g. a caller
   *  that rebuilds the channel every call instead of reusing one across a
   *  scheduled loop) starts with this empty and re-clears once, same as
   *  before this existed — the skip only helps a REUSED channel instance. */
  const clearedNodes = new Set<string>()

  let result: SpaceMirrorResult = { spaces: {}, created: [], written: [], skipped: [], cleared: [] }

  function docPullPath(spaceId: string, nodeId: string): string {
    return `/pull/${opts.docPath(spaceId, nodeId)}`
  }
  function docPushPath(spaceId: string, nodeId: string): string {
    return `/push/${opts.docPath(spaceId, nodeId)}`
  }

  async function findOrCreateNode(
    spaceId: string,
    existing: ExistingSpaceNode | undefined,
    id: string,
  ): Promise<{ id: string }> {
    if (existing) return existing
    return port.createNode(opts.session, spaceId, {
      type: id,
      title: id,
      ...nodeEnc,
    } as CreateNodeInput)
  }

  /** CAS-write a raw (uncurated) projection into one node — no field
   *  allowlist, no merge: whatever `data` is IS the node's content after
   *  this call. */
  async function writeNode(spaceId: string, nodeId: string, data: unknown): Promise<void> {
    const handle = await port.getNodeAccess(spaceId, nodeId, nodeEnc, opts.session)
    await handle.push(
      docPullPath(spaceId, nodeId),
      docPushPath(spaceId, nodeId),
      () => (data ?? {}) as Record<string, unknown>,
    )
  }

  /** Clear a disabled collection's node content — stale data must not sit
   *  there encrypted under the space key indefinitely once the user opts out. */
  async function clearNode(spaceId: string, nodeId: string): Promise<void> {
    const handle = await port.getNodeAccess(spaceId, nodeId, nodeEnc, opts.session)
    await handle.push(docPullPath(spaceId, nodeId), docPushPath(spaceId, nodeId), () => ({}))
  }

  async function syncOneSpace(
    spaceName: string,
    enabledIds: readonly string[],
    ctx: ReplicaCallContext,
  ): Promise<{
    spaceId: string | null
    created: string[]
    written: string[]
    skipped: string[]
    cleared: string[]
  }> {
    // Only the collections that actually belong in THIS space.
    const collectionsForThisSpace = enabledIds.filter(
      (id) => knownIds.has(id) && spaceNameFor.get(id) === spaceName,
    )

    // Don't create an empty space just to immediately clear nothing in it —
    // if nothing is currently enabled for this space AND the space was never
    // created before (nothing to clear either), skip it entirely. A space
    // that DOES already exist (e.g. every collection routed here just got
    // disabled) is still resolved below so its now-orphaned nodes get cleared.
    if (collectionsForThisSpace.length === 0) {
      const doc = await port.readSpaces(opts.session)
      const existing = doc.spaces.find((space) => space.name === spaceName)
      if (!existing) return { spaceId: null, created: [], written: [], skipped: [], cleared: [] }
    }

    const space = await findOrCreateSpace(opts.session, spaceName, port)
    const tree = await port.readObjectTree(opts.session, space.id)
    const existingNodes: ExistingSpaceNode[] = tree
      .filter((node) => knownIds.has(node.type))
      .map((node) => ({ id: node.id, type: node.type }))

    const plan = planSpaceMirror(existingNodes, collectionsForThisSpace, knownIds)
    const existingByType = new Map(existingNodes.map((n) => [n.type, n]))

    const written: string[] = []
    const skipped: string[] = []
    for (const id of plan.toWrite) {
      const existing = existingByType.get(id)
      const node = await findOrCreateNode(space.id, existing, id)
      const data = await opts.readSource(id, ctx)

      if (changeDetection === "source-hash" && existing) {
        const hash = fingerprint(data)
        if (lastWritten.get(node.id) === hash) {
          skipped.push(id)
          continue
        }
        await writeNode(space.id, node.id, data)
        lastWritten.set(node.id, hash)
      } else {
        await writeNode(space.id, node.id, data)
        if (changeDetection === "source-hash") lastWritten.set(node.id, fingerprint(data))
      }
      // A node just written to is no longer "already cleared" — if it gets
      // disabled again later it needs a real clear, not a skip.
      clearedNodes.delete(node.id)
      written.push(id)
    }

    for (const node of plan.toClear) {
      // Already cleared in a prior cycle and never re-enabled since — a
      // repeat push would be a no-op CAS write wasted every cycle this
      // channel instance is reused for (e.g. via a persistent
      // ReplicaManager-driven scheduled loop).
      if (clearedNodes.has(node.id)) continue
      await clearNode(space.id, node.id)
      clearedNodes.add(node.id)
      lastWritten.delete(node.id)
    }

    return {
      spaceId: space.id,
      created: plan.toCreate,
      written,
      skipped,
      cleared: plan.toClear.map((n) => n.type),
    }
  }

  return {
    name: opts.name,
    get result(): SpaceMirrorResult {
      return result
    },
    async sync(ctx: ReplicaCallContext): Promise<void> {
      const enabledIds = await opts.enabledIds()
      // The spaces are independent (different id, different keyring, no
      // shared state) — run them concurrently rather than paying sequential
      // network round trips per space every cycle.
      const perSpace = await Promise.all(
        spaceNames.map((spaceName) => syncOneSpace(spaceName, enabledIds, ctx)),
      )
      const spaces: Record<string, string | null> = {}
      const created: string[] = []
      const written: string[] = []
      const skipped: string[] = []
      const cleared: string[] = []
      spaceNames.forEach((spaceName, i) => {
        const r = perSpace[i]!
        spaces[spaceName] = r.spaceId
        created.push(...r.created)
        written.push(...r.written)
        skipped.push(...r.skipped)
        cleared.push(...r.cleared)
      })
      result = { spaces, created, written, skipped, cleared }
    },
  }
}
