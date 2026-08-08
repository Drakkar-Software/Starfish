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
  type NodeAccessHandle,
  type Session,
  type SpacePort,
} from "./port.js"

/**
 * Storage tier for one collection's node — a single closed enum, deliberately
 * NOT a raw `{ access, enc }` pair. The server rejects `access:"public"` with
 * `enc:true` (a world-readable document sealed under a keyring nobody outside
 * the space can open is not a thing it will store), and an enum makes that
 * combination unrepresentable at the type level instead of a runtime failure
 * discovered late, at `createNode`, after a space has already been created.
 *
 * - `"private"` -> the channel-wide `nodeEnc`, itself
 *   `{ access: "space", enc: true }` unless the caller overrode it: readable
 *   only by space members, sealed under the space's own keyring.
 * - `"isolated"` -> `{ access: "invite", enc: true }`, always, ignoring
 *   `nodeEnc`: sealed under the node's OWN keyring, so access can be granted
 *   and revoked one node at a time without space membership.
 * - `"public"`  -> `{ access: "public", enc: false }`, always, ignoring
 *   `nodeEnc`: world-readable plaintext at its storage URL. Only ever for
 *   content the user explicitly chose to publish.
 */
export type SpaceMirrorTier = "private" | "isolated" | "public"

/** One collection this channel mirrors, and which space its node lives in. */
export interface SpaceMirrorCollection {
  id: string
  spaceName: string
  /** Storage tier for THIS collection's node. Defaults to `"private"`, and
   *  spelling `"private"` out is EXACTLY equivalent to omitting it — both
   *  resolve to the channel-wide `nodeEnc`. (An explicit `"private"` that
   *  ignored a caller's custom `nodeEnc` would make the documented default a
   *  lie.) Only `"public"` changes anything: it overrides `nodeEnc` with the
   *  fixed world-readable-plaintext pair. */
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
  /** Ids whose write (or clear) threw this cycle — an oversized document, a
   *  CAS 409 that exhausted its retries, a transient network error. The rest
   *  of the cycle still ran, so the ids in `written`/`cleared` really were
   *  written/cleared despite these failures. A whole space failing (its space
   *  doc or object tree could not even be read) contributes EVERY collection
   *  routed to that space. The underlying errors are NOT swallowed: `sync()`
   *  still rejects with an `AggregateError` once the cycle has finished and
   *  this result has been assigned, so `ChannelScheduler`'s `_onError` funnel
   *  sees them while `channel.result` still tells the truth about the cycle. */
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
   *  passed first so a caller can route a tier (or any other per-collection
   *  concern) to a different path prefix — e.g. a stable, guessable path for a
   *  public collection whose URL is meant to be shared. On the CLEAR path the
   *  collection id is the existing node's `type`. */
  docPath: (collectionId: string, spaceId: string, nodeId: string) => string
  /** Human-readable node title, used only when a node is first created.
   *  Default: the collection id itself. */
  title?: (collectionId: string) => string
  /** Node access/encryption mode for collections that do NOT set their own
   *  `tier`. Default: `{ access: "space", enc: true }` — content gated by
   *  space membership, encrypted under the space's own keyring. Use
   *  `tier: "isolated"` rather than setting `access: "invite"` here: the tier
   *  also seeds the per-node keyring, which this raw override does not. */
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

/** The `tier: "public"` resolution. Deliberately NOT influenced by `nodeEnc`:
 *  `access:"public"` with `enc:true` is a combination the server rejects, and
 *  the whole point of a single `tier` enum is that it cannot be expressed. */
const PUBLIC_NODE_ENC: Readonly<{ access: NodeAccess; enc: boolean }> = Object.freeze({
  access: "public" as NodeAccess,
  enc: false,
})

/** The `tier: "isolated"` resolution. Like `PUBLIC_NODE_ENC`, not influenced by
 *  `nodeEnc` — the tier IS the access model. */
const ISOLATED_NODE_ENC: Readonly<{ access: NodeAccess; enc: boolean }> = Object.freeze({
  access: "invite" as NodeAccess,
  enc: true,
})

const DEFAULT_TIER: SpaceMirrorTier = "private"

/** Every tier, so a fingerprint sweep can drop all of a node's keys at once. */
const ALL_TIERS: readonly SpaceMirrorTier[] = ["private", "isolated", "public"]

type NodeAxes = { access: NodeAccess; enc: boolean }

/** Whether these axes are the isolated tier's — true wherever they come from,
 *  including a node's STORED axes on the clear path. */
function isIsolated(axes: { access?: NodeAccess; enc?: boolean }): boolean {
  return axes.access === "invite" && axes.enc === true
}

/** The axes a node is ACTUALLY stored under, normalized from what the object
 *  index records. `starfish-spaces`' node creation omits `access` when it is
 *  `"space"` and `enc` when false, so an absent field is the default, not a
 *  gap — normalizing here is what makes a stored-vs-configured comparison
 *  meaningful instead of "everything looks flipped". */
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

  /** The ONE place a tier turns into the `{ access, enc }` pair the port
   *  speaks.
   *
   *  `"private"` resolves to the channel-wide `nodeEnc` (itself
   *  `{ access: "space", enc: true }` unless the caller overrode it) rather
   *  than to a hardcoded pair, and it does so whether the tier was written out
   *  explicitly or left to default. `tier` DEFAULTS to `"private"`, so
   *  `tier: "private"` and an omitted `tier` have to resolve identically or
   *  the documented default is a lie — a caller who passes a custom `nodeEnc`
   *  and spells out `tier: "private"` would silently lose the override.
   *  `"public"` and `"isolated"` are fixed pairs and ignore `nodeEnc`. */
  function axesForTier(tier: SpaceMirrorTier): NodeAxes {
    if (tier === "public") return { ...PUBLIC_NODE_ENC }
    if (tier === "isolated") return { ...ISOLATED_NODE_ENC }
    return { ...nodeEnc }
  }

  /** collectionId -> its tier and the `{ access, enc }` that tier resolves to.
   *  Precomputed rather than derived per write: the write/clear hot path is a
   *  single Map lookup, and the `access:"public" + enc:true` combination the
   *  server rejects can never be assembled here at all.
   *
   *  Refreshed once at the TOP of each cycle (see `refreshTiers`) for the same
   *  reason `enabledIds` is read fresh every cycle: a settings toggle that
   *  republishes a collection under a different tier must apply on the next
   *  cycle of an already-running channel, not only after the caller rebuilds
   *  it. Per-cycle, not per-collection — it stays O(collections) once. */
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

  /** `${nodeId}:${tier}` -> fingerprint of the data last written under THAT
   *  tier. Only consulted under `changeDetection: "source-hash"`. Keyed by
   *  tier, not by node id alone, because flipping a collection's tier does not
   *  change what `readSource` returns — so a node-id-keyed hash would match
   *  and skip the ONE write that actually migrates the node to its new tier. */
  const lastWritten = new Map<string, string>()
  /** Drop EVERY tier's fingerprint for one node. Used wherever the node's
   *  stored content stops matching what any fingerprint claims — a clear, or a
   *  flip's clear. Popping only the tier just handled would leave the OTHER
   *  tier's stale fingerprint to skip a later write back to it. */
  function forgetFingerprints(nodeId: string): void {
    for (const tier of ALL_TIERS) lastWritten.delete(`${nodeId}:${tier}`)
  }
  /** nodeIds already cleared by a prior cycle of THIS channel instance —
   *  skips a repeat no-op CAS write for a node that's stayed disabled since.
   *  Per-instance, not per-space-content: a fresh channel (e.g. a caller
   *  that rebuilds the channel every call instead of reusing one across a
   *  scheduled loop) starts with this empty and re-clears once, same as
   *  before this existed — the skip only helps a REUSED channel instance. */
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
    // THIS collection's resolved tier, not the channel-wide default — a public
    // collection has to be born public; creating it under the space keyring
    // and "fixing" it later would publish nothing readable at its URL.
    return port.createNode(opts.session, spaceId, {
      type: id,
      title: titleFor(id),
      ...resolve(id).enc,
    } as CreateNodeInput)
  }

  /** Resolve the handle to read/write one node under `enc`.
   *
   *  `getNodeAccess` already routes `invite`+`enc` to the node's OWN keyring
   *  with the throwing variant (no space-keyring fallback) — but it only OPENS
   *  that keyring, so an isolated node needs it created first or its very
   *  first write throws. */
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

  /** Clear a disabled collection's node content — stale data must not sit
   *  there encrypted under the space key indefinitely once the user opts out,
   *  and must not sit there in PLAINTEXT at a world-readable URL for a public
   *  one. `enc` is the tier the content being cleared was written under, which
   *  on a tier flip is the OLD one, not the collection's current tier. */
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
  ): Promise<{
    spaceId: string | null
    created: string[]
    written: string[]
    skipped: string[]
    cleared: string[]
    failed: string[]
    /** The raw throwables behind `failed`, kept so `sync()` can rethrow them
     *  instead of reducing a real failure to a string in a list. */
    errors: unknown[]
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
      if (!existing)
        return {
          spaceId: null,
          created: [],
          written: [],
          skipped: [],
          cleared: [],
          failed: [],
          errors: [],
        }
    }

    const space = await findOrCreateSpace(opts.session, spaceName, port)
    const tree = await port.readObjectTree(opts.session, space.id)
    // `access`/`enc` are carried through, not narrowed away: they are the
    // node's STORED tier evidence, and the only kind that survives this
    // channel being rebuilt (an app restart, a caller that constructs a fresh
    // channel per call). Without them a flip made while this instance did not
    // exist is invisible.
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
    // Accumulated from what findOrCreateNode ACTUALLY created, not from
    // plan.toCreate — the plan says what should be created, and a create that
    // throws must not be reported as though it had happened. Otherwise the same
    // id lands in both `created` and `failed`, which is worse than either
    // alone: a caller reconciling the two cannot tell whether the node exists.
    const created: string[] = []
    for (const id of plan.toWrite) {
      // Per-collection isolation: ONE collection blowing up (a 413 on an
      // oversized document, a CAS 409 that exhausted its retries, a network
      // blip) used to throw straight out of this loop and cost every other
      // collection — in every space — its write for the cycle. Record which
      // one failed, keep going; `sync()` rethrows the collected errors once
      // the whole cycle has run, so nothing is silently dropped.
      try {
        const existing = existingByType.get(id)
        const { tier, enc } = resolve(id)
        const node = await findOrCreateNode(space.id, existing, id)
        if (!existing) created.push(id)
        // Set when this cycle migrated the node between tiers, so the STORED
        // axes can be patched to match once the new content is safely written.
        let flipped = false

        // Tier flip, detected from what is STORED rather than from what this
        // instance remembers writing. The realistic flip is a user toggling a
        // collection in settings and the app restarting or rebuilding the
        // channel — at which point an in-memory "last tier I wrote" map is
        // empty and would report no flip at all, leaving a public -> private
        // collection's old plaintext at its world-readable URL indefinitely.
        // That is the exact hazard this clear exists to prevent.
        //
        // Cleared under the STORED axes, not the configured ones: the new axes
        // resolve a different handle, which does not reach (or decrypt) what is
        // actually sitting there. Done before `readSource` so a failing source
        // cannot leave the old copy behind either.
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

        // The flip is only finished once the INDEX agrees with the content.
        // Strictly AFTER the write, never before: patching first would leave
        // the index claiming a tier the stored content does not match if the
        // write then failed. Two things go wrong without this:
        //
        // 1. Privacy. Infra's public-objects projection extracts every node
        //    whose stored `access` is `"public"` out of an `objindex` write
        //    and upserts `{ id, title, type, updatedAt }` into a
        //    world-readable index. A collection flipped public -> private has
        //    its CONTENT cleared, but its node keeps being advertised — id,
        //    title and type — to anonymous callers indefinitely, contradicting
        //    the setting the user just changed.
        // 2. The flip would never be self-limiting: the stored axes still read
        //    as the old tier next cycle, so the clear re-fires forever and a
        //    `source-hash` collection can never skip again.
        //
        // The patch normalizes exactly like `createNode` (no `access` for
        // `"space"`, no `enc` when false), so the node ends up
        // indistinguishable from one born at this tier.
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
      // The axes the content being cleared was actually written under, read
      // off the object index rather than remembered: a channel rebuilt since
      // the write has nothing to remember, and the configured tier may since
      // have been flipped to something that does not reach the stored copy.
      const clearEnc = storedAxes(node)
      const configured = resolve(node.type)
      // Reachable from outside the space's own membership on EITHER side —
      // what is stored, or what it is configured as now.
      const reachable = (a: { access?: NodeAccess }) =>
        a.access === "public" || a.access === "invite"
      const touchesExternal = reachable(clearEnc) || reachable(configured.enc)
      // Already cleared in a prior cycle and never re-enabled since — a
      // repeat push would be a no-op CAS write wasted every cycle this
      // channel instance is reused for (e.g. via a persistent
      // ReplicaManager-driven scheduled loop). NOT applied to a public or
      // isolated node: there the skip is not symmetric with the space-private
      // case. A private node this channel wrongly believes it already cleared
      // leaves stale ciphertext readable only by space members; a public one
      // leaves stale PLAINTEXT at a world-readable URL, and an isolated one
      // leaves stale content readable by every holder of a still-valid
      // per-node grant. Pay the redundant no-op CAS write every cycle rather
      // than ever bet on that belief.
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
        // Same isolation as a write, plus: `clearedNodes` deliberately does
        // NOT get the node id, so the next cycle retries the clear instead of
        // treating stale content as already gone.
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
      // Same reason `enabledIds` is read fresh: a settings change that moves a
      // collection between tiers must take effect on the next cycle of an
      // already-running channel, not only after the caller rebuilds it.
      refreshTiers()
      const enabledIds = await opts.enabledIds()
      // The spaces are independent (different id, different keyring, no
      // shared state) — run them concurrently rather than paying sequential
      // network round trips per space every cycle.
      const perSpace = await Promise.all(
        spaceNames.map(async (spaceName) => {
          try {
            return await syncOneSpace(spaceName, enabledIds, ctx)
          } catch (e) {
            // A space-level failure (its space registry entry, its object
            // tree) sinks only THIS space — a rejected `Promise.all` used to
            // throw away every other space's already-completed work too.
            // Nothing routed here got mirrored, so every collection of this
            // space is reported failed.
            return {
              spaceId: null,
              created: [],
              written: [],
              skipped: [],
              cleared: [],
              failed: opts.collections
                .filter((c) => c.spaceName === spaceName)
                .map((c) => c.id),
              errors: [e],
            }
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
      // Assigned BEFORE the rethrow below: a cycle that partly failed must
      // still replace `result`, or a caller reading `channel.result` after a
      // bad cycle gets the previous cycle's numbers and believes them.
      result = { spaces, created, written, skipped, cleared, failed }

      if (errors.length > 0) {
        // Counted is not the same as surfaced. `ChannelScheduler` funnels a
        // rejected `sync()` into its `_onError` handler (console.error by
        // default), which is this package's one error surface — so keep
        // rejecting, just AFTER the whole cycle ran and with the failing
        // collection ids named, which is exactly what the old blind throw
        // could not tell the caller.
        throw new AggregateError(
          errors,
          `[Starfish] Space mirror "${opts.name}": ${failed.length} collection(s) failed to sync: ${failed.join(", ")}`,
        )
      }
    },
  }
}
