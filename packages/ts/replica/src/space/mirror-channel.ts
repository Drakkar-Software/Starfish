/**
 * A `ReplicaChannel` that mirrors an app-local data source into per-collection
 * nodes of one or more Starfish spaces. This module owns the space/node
 * mechanics — space find-or-create, node find-or-create, CAS-write,
 * clear-on-disable, and routing across several spaces. What stays with the
 * caller is the collection registry (which ids exist, which space each routes
 * to) and the `readSource` callback.
 *
 * Each collection picks a storage `tier`: `private` (space keyring),
 * `isolated` (per-node keyring, grantable one node at a time) or `public`
 * (plaintext). See `website/docs/extensions/replica.md`.
 */
import type { ReplicaCallContext, ReplicaChannel } from "../channel.js"
import { planSpaceMirror, type ExistingSpaceNode } from "./plan.js"
import {
  defaultSpacePort,
  findOrCreateSpace,
  type CreateNodeInput,
  type NodeAccess,
  type NodeAccessHandle,
  type Session,
  type SpacePort,
} from "./port.js"

/**
 * Storage tier for one collection's node: a closed enum, NOT a raw
 * `{ access, enc }` pair: the server rejects `access:"public"` with `enc:true`,
 * and an enum makes that combination unrepresentable instead of a runtime
 * failure discovered late, at `createNode`.
 *
 * - `"private"`  -> the channel-wide `nodeEnc` (default
 *   `{ access: "space", enc: true }`): space members only, space keyring.
 * - `"isolated"` -> `{ access: "invite", enc: true }`: the node's OWN keyring,
 *   so access is granted and revoked one node at a time, without membership.
 * - `"public"`   -> `{ access: "public", enc: false }`: world-readable plaintext.
 */
export type SpaceMirrorTier = "private" | "isolated" | "public"

/** One collection this channel mirrors, and which space its node lives in. */
export interface SpaceMirrorCollection {
  id: string
  spaceName: string
  /** Storage tier for THIS collection's node. Default `"private"`, which is
   *  EXACTLY equivalent to omitting it: both resolve to the channel-wide
   *  `nodeEnc`, or the documented default would be a lie. `"isolated"` and
   *  `"public"` are fixed pairs that ignore `nodeEnc`. */
  tier?: SpaceMirrorTier
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
  /** Ids whose write or clear threw this cycle; the rest of the cycle still
   *  ran. A whole space failing (space doc or object tree unreadable)
   *  contributes EVERY collection routed to it. Not swallowed: `sync()`
   *  rejects with an `AggregateError` once this result has been assigned. */
  failed: string[]
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
   *  prefix — this channel adds that). E.g. `(collectionId, spaceId, nodeId)
   *  => \`spaces/${spaceId}/objects/mirror/${nodeId}\``. The collection id is
   *  passed first so a caller can route a tier to a different path prefix. On
   *  the CLEAR path it is the existing node's `type`. */
  docPath: (collectionId: string, spaceId: string, nodeId: string) => string
  /** Human-readable node title, used only when a node is first created.
   *  Default: the collection id itself. */
  title?: (collectionId: string) => string
  /** Node access/encryption for collections that do NOT set their own `tier`.
   *  Default `{ access: "space", enc: true }`. Use `tier: "isolated"` rather
   *  than `access: "invite"` here: only the tier seeds the per-node keyring. */
  nodeEnc?: { access?: NodeAccess; enc?: boolean }
  /**
   * `"none"` (default): write every enabled collection every cycle.
   * `"source-hash"`: skip an already-existing node's write when `readSource`'s
   * result is byte-identical to what this channel last wrote. ONLY safe when
   * this channel is the SOLE writer: a skip never re-checks what is actually
   * stored, so a second writer could silently diverge from what it assumes.
   */
  changeDetection?: "none" | "source-hash"
  /** Override the `starfish-spaces` calls (tests). Default: the real SDK. */
  port?: SpacePort
}

const DEFAULT_NODE_ENC: { access: NodeAccess; enc: boolean } = { access: "space", enc: true }

// Fixed pairs, deliberately NOT influenced by `nodeEnc`: for these two tiers
// the tier IS the access model, and `access:"public"` + `enc:true` is a
// combination the server rejects, so the enum must make it inexpressible.
const PUBLIC_NODE_ENC: Readonly<{ access: NodeAccess; enc: boolean }> = Object.freeze({
  access: "public" as NodeAccess,
  enc: false,
})
const ISOLATED_NODE_ENC: Readonly<{ access: NodeAccess; enc: boolean }> = Object.freeze({
  access: "invite" as NodeAccess,
  enc: true,
})

const DEFAULT_TIER: SpaceMirrorTier = "private"

/** Every tier, so a fingerprint sweep can drop all of a node's keys at once. */
const ALL_TIERS: readonly SpaceMirrorTier[] = ["private", "isolated", "public"]

type NodeAxes = { access: NodeAccess; enc: boolean }

/** One space's contribution to a cycle. Mirrors Python's `_SpaceOutcome`. */
interface SpaceOutcome {
  spaceId: string | null
  created: string[]
  written: string[]
  skipped: string[]
  cleared: string[]
  failed: string[]
  /** The raw throwables behind `failed`, so `sync()` can rethrow them instead
   *  of reducing a real failure to a string in a list. */
  errors: unknown[]
}

/** `SpaceOutcome` defaults, matching Python's `_SpaceOutcome()`. */
function emptyOutcome(patch: Partial<SpaceOutcome> = {}): SpaceOutcome {
  return {
    spaceId: null,
    created: [],
    written: [],
    skipped: [],
    cleared: [],
    failed: [],
    errors: [],
    ...patch,
  }
}

function isIsolated(axes: { access?: NodeAccess; enc?: boolean }): boolean {
  return axes.access === "invite" && axes.enc === true
}

/** Reachable by someone other than this space's members: `public` by the
 *  world, `invite` by every holder of a still-valid per-node grant. */
function isExternal(axes: { access?: NodeAccess }): boolean {
  return axes.access === "public" || axes.access === "invite"
}

/** The axes a node is ACTUALLY stored under, normalized: `starfish-spaces`'
 *  node creation omits `access` when it is `"space"` and `enc` when false, so
 *  an absent field is the default, not a gap. */
function storedAxes(node: ExistingSpaceNode): NodeAxes {
  return { access: (node.access ?? "space") as NodeAccess, enc: node.enc === true }
}

function sameAxes(a: NodeAxes, b: NodeAxes): boolean {
  return a.access === b.access && a.enc === b.enc
}

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
  const titleFor = opts.title ?? ((id: string) => id)
  const knownIds = new Set(opts.collections.map((c) => c.id))
  const spaceNameFor = new Map(opts.collections.map((c) => [c.id, c.spaceName]))
  const spaceNames = [...new Set(opts.collections.map((c) => c.spaceName))]

  /** The ONE place a tier becomes the `{ access, enc }` pair the port speaks.
   *  `"private"` (explicit or defaulted) resolves to the channel-wide
   *  `nodeEnc`, so a caller's override survives either spelling. */
  function axesForTier(tier: SpaceMirrorTier): NodeAxes {
    if (tier === "public") return { ...PUBLIC_NODE_ENC }
    if (tier === "isolated") return { ...ISOLATED_NODE_ENC }
    return { ...nodeEnc }
  }

  /** collectionId -> its tier and resolved `{ access, enc }`. Refreshed at the
   *  TOP of each cycle, like `enabledIds`, so a settings toggle that moves a
   *  collection to another tier applies to an already-running channel. */
  const resolvedFor = new Map<string, { tier: SpaceMirrorTier; enc: NodeAxes }>()
  function refreshTiers(): void {
    for (const c of opts.collections) {
      const tier = c.tier ?? DEFAULT_TIER
      resolvedFor.set(c.id, { tier, enc: axesForTier(tier) })
    }
  }
  refreshTiers()

  function resolve(id: string): { tier: SpaceMirrorTier; enc: NodeAxes } {
    return resolvedFor.get(id) ?? { tier: DEFAULT_TIER, enc: axesForTier(DEFAULT_TIER) }
  }

  /** `${nodeId}:${tier}` -> fingerprint last written under THAT tier, only
   *  consulted under `changeDetection: "source-hash"`. Keyed by tier because
   *  flipping tiers does not change what `readSource` returns, so a
   *  node-id-only key would skip the ONE write that migrates the node. */
  const lastWritten = new Map<string, string>()
  /** Drop EVERY tier's fingerprint for a node whose stored content no longer
   *  matches any of them; popping only the tier just handled would leave the
   *  other's stale fingerprint to skip a later write back to it. */
  function forgetFingerprints(nodeId: string): void {
    for (const tier of ALL_TIERS) lastWritten.delete(`${nodeId}:${tier}`)
  }
  /** nodeIds already cleared by a prior cycle of THIS channel instance —
   *  skips a repeat no-op CAS write. Per-instance, so a channel rebuilt every
   *  call simply re-clears once, as if this did not exist. */
  const clearedNodes = new Set<string>()

  let result: SpaceMirrorResult = {
    spaces: {},
    created: [],
    written: [],
    skipped: [],
    cleared: [],
    failed: [],
  }

  function docPullPath(collectionId: string, spaceId: string, nodeId: string): string {
    return `/pull/${opts.docPath(collectionId, spaceId, nodeId)}`
  }
  function docPushPath(collectionId: string, spaceId: string, nodeId: string): string {
    return `/push/${opts.docPath(collectionId, spaceId, nodeId)}`
  }

  async function findOrCreateNode(
    spaceId: string,
    existing: ExistingSpaceNode | undefined,
    id: string,
  ): Promise<{ id: string }> {
    if (existing) return existing
    // THIS collection's resolved tier, not the channel-wide default: a public
    // collection has to be born public, or nothing readable sits at its URL.
    return port.createNode(opts.session, spaceId, {
      type: id,
      title: titleFor(id),
      ...resolve(id).enc,
    } as CreateNodeInput)
  }

  /** Handle to read/write one node under `enc`. `getNodeAccess` routes
   *  `invite`+`enc` to the node's OWN keyring but only OPENS it, so an
   *  isolated node needs that keyring created or its first write throws. */
  async function accessFor(
    spaceId: string,
    nodeId: string,
    enc: { access: NodeAccess; enc: boolean },
  ): Promise<NodeAccessHandle> {
    if (isIsolated(enc)) await port.ensureNodeKeyring(opts.session, spaceId, nodeId)
    return port.getNodeAccess(spaceId, nodeId, enc, opts.session)
  }

  /** CAS-write a raw (uncurated) projection into one node — no field
   *  allowlist, no merge: whatever `data` is IS the node's content after
   *  this call. */
  async function writeNode(
    collectionId: string,
    spaceId: string,
    nodeId: string,
    data: unknown,
    enc: { access: NodeAccess; enc: boolean },
  ): Promise<void> {
    const handle = await accessFor(spaceId, nodeId, enc)
    await handle.push(
      docPullPath(collectionId, spaceId, nodeId),
      docPushPath(collectionId, spaceId, nodeId),
      () => (data ?? {}) as Record<string, unknown>,
    )
  }

  /** Clear a disabled collection's node content: stale data must not sit there
   *  encrypted once the user opts out, and must REALLY not sit there in
   *  plaintext at a public URL. `enc` is the tier the content being cleared was
   *  written under, which on a flip is the OLD one, not the current tier. */
  async function clearNode(
    collectionId: string,
    spaceId: string,
    nodeId: string,
    enc: { access: NodeAccess; enc: boolean },
  ): Promise<void> {
    const handle = await accessFor(spaceId, nodeId, enc)
    await handle.push(
      docPullPath(collectionId, spaceId, nodeId),
      docPushPath(collectionId, spaceId, nodeId),
      () => ({}),
    )
  }

  async function syncOneSpace(
    spaceName: string,
    enabledIds: readonly string[],
    ctx: ReplicaCallContext,
  ): Promise<SpaceOutcome> {
    const collectionsForThisSpace = enabledIds.filter(
      (id) => knownIds.has(id) && spaceNameFor.get(id) === spaceName,
    )

    // Don't create an empty space just to clear nothing in it. One that DOES
    // already exist is still resolved below, so its orphaned nodes get cleared.
    if (collectionsForThisSpace.length === 0) {
      const doc = await port.readSpaces(opts.session)
      const existing = doc.spaces.find((space) => space.name === spaceName)
      if (!existing) return emptyOutcome()
    }

    const space = await findOrCreateSpace(opts.session, spaceName, port)
    const tree = await port.readObjectTree(opts.session, space.id)
    // `access`/`enc` are the node's STORED tier evidence, the only kind that
    // survives this channel being rebuilt. Without them a flip made while this
    // instance did not exist is invisible.
    const existingNodes: ExistingSpaceNode[] = tree
      .filter((node) => knownIds.has(node.type))
      .map((node) => ({ id: node.id, type: node.type, access: node.access, enc: node.enc }))

    const plan = planSpaceMirror(existingNodes, collectionsForThisSpace, knownIds)
    const existingByType = new Map(existingNodes.map((n) => [n.type, n]))

    const written: string[] = []
    const skipped: string[] = []
    const cleared: string[] = []
    const failed: string[] = []
    const errors: unknown[] = []
    // What findOrCreateNode ACTUALLY created, not plan.toCreate: an id landing
    // in both `created` and `failed` leaves a caller unable to tell whether
    // the node exists.
    const created: string[] = []
    for (const id of plan.toWrite) {
      // Per-collection isolation: one node's 413, exhausted CAS 409, or
      // network blip must not cost the OTHERS their write. `sync()` rethrows
      // the collected errors once the whole cycle has run.
      try {
        const existing = existingByType.get(id)
        const { tier, enc } = resolve(id)
        const node = await findOrCreateNode(space.id, existing, id)
        if (!existing) created.push(id)
        let flipped = false

        // Tier flip, detected from what is STORED, not from what this instance
        // remembers: after a restart there is nothing to remember, and a
        // public -> private flip would leave the old plaintext at its
        // world-readable URL indefinitely. Cleared FIRST and under the STORED
        // axes, since the new ones resolve a handle that cannot reach it.
        if (existing && !sameAxes(storedAxes(existing), enc)) {
          await clearNode(id, space.id, node.id, storedAxes(existing))
          forgetFingerprints(node.id)
          flipped = true
        }

        const data = await opts.readSource(id, ctx)
        const hashKey = `${node.id}:${tier}`

        if (changeDetection === "source-hash" && existing) {
          const hash = fingerprint(data)
          if (lastWritten.get(hashKey) === hash) {
            skipped.push(id)
            continue
          }
          await writeNode(id, space.id, node.id, data, enc)
          lastWritten.set(hashKey, hash)
        } else {
          await writeNode(id, space.id, node.id, data, enc)
          if (changeDetection === "source-hash") lastWritten.set(hashKey, fingerprint(data))
        }

        // Strictly AFTER the write: patching first would leave the index
        // claiming a tier the stored content does not match, had the write
        // failed. Without the patch a node flipped away from `"public"` stays
        // advertised (id, title, type) in Infra's world-readable public-objects
        // projection, and the clear re-fires every cycle.
        if (flipped) await port.setNodeAccess(opts.session, space.id, node.id, enc)

        // A node just written to is no longer "already cleared" — if it gets
        // disabled again later it needs a real clear, not a skip.
        clearedNodes.delete(node.id)
        written.push(id)
      } catch (e) {
        errors.push(e)
        failed.push(id)
      }
    }

    for (const node of plan.toClear) {
      // The axes the content was actually written under, read off the object
      // index rather than remembered: a rebuilt channel remembers nothing, and
      // the configured tier may since have flipped away from the stored copy.
      const clearEnc = storedAxes(node)
      // External on EITHER side — what is stored, or what it is configured as.
      const touchesExternal = isExternal(clearEnc) || isExternal(resolve(node.type).enc)
      // Skip a repeat no-op CAS write. SPACE-PRIVATE ONLY: `clearedNodes` is
      // only ever a BELIEF about server state (a rolled-back clear, another
      // writer, a node recreated under the same id), cheap to re-assert and
      // unacceptable to get wrong for content readable by the world or by
      // every existing grant holder.
      if (!touchesExternal && clearedNodes.has(node.id)) {
        cleared.push(node.type)
        continue
      }
      try {
        await clearNode(node.type, space.id, node.id, clearEnc)
        clearedNodes.add(node.id)
        forgetFingerprints(node.id)
        cleared.push(node.type)
      } catch (e) {
        // `clearedNodes` deliberately does NOT get the node id, so the next
        // cycle retries the clear instead of treating stale content as gone.
        errors.push(e)
        failed.push(node.type)
      }
    }

    return {
      spaceId: space.id,
      created,
      written,
      skipped,
      cleared,
      failed,
      errors,
    }
  }

  return {
    name: opts.name,
    get result(): SpaceMirrorResult {
      return result
    },
    async sync(ctx: ReplicaCallContext): Promise<void> {
      refreshTiers()
      const enabledIds = await opts.enabledIds()
      // Independent spaces (different id, different keyring, no shared state).
      const perSpace = await Promise.all(
        spaceNames.map(async (spaceName) => {
          try {
            return await syncOneSpace(spaceName, enabledIds, ctx)
          } catch (e) {
            // Raised BEFORE the per-collection loops (space resolve, tree
            // read), so every id declared for this space is a failure, not
            // just the enabled ones.
            return emptyOutcome({
              failed: opts.collections
                .filter((c) => c.spaceName === spaceName)
                .map((c) => c.id),
              errors: [e],
            })
          }
        }),
      )
      const spaces: Record<string, string | null> = {}
      const created: string[] = []
      const written: string[] = []
      const skipped: string[] = []
      const cleared: string[] = []
      const failed: string[] = []
      const errors: unknown[] = []
      spaceNames.forEach((spaceName, i) => {
        const r = perSpace[i]!
        spaces[spaceName] = r.spaceId
        created.push(...r.created)
        written.push(...r.written)
        skipped.push(...r.skipped)
        cleared.push(...r.cleared)
        failed.push(...r.failed)
        errors.push(...r.errors)
      })
      // Assigned BEFORE the rethrow below: a stale previous result read as if
      // it were this cycle's is worse than an honest partial one.
      result = { spaces, created, written, skipped, cleared, failed }

      if (errors.length > 0) {
        // Feeds `ChannelScheduler`'s `_onError` funnel, the package's single
        // error surface. The cycle has fully run here, so this is "finished
        // with failures", not an abort.
        throw new AggregateError(
          errors,
          `[Starfish] Space mirror "${opts.name}": ${failed.length} collection(s) failed to sync: ${failed.join(", ")}`,
        )
      }
    },
  }
}
