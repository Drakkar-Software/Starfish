/**
 * Server plugin for the projection (incremental-list) extension.
 *
 * Implements the `afterWrite` write-path hook from the `ServerPlugin` contract:
 * after a successful push the server hands the plugin a `WriteEvent`; for any
 * projection whose `source` includes the event's collection, the plugin runs the
 * app-supplied pure `project(event)` mapping and folds its outcome into a single
 * target *list document* — appending a new entry, replacing an existing one in
 * place, or removing it (`null` = ignore). The app supplies only the mapping; the
 * plugin owns all store IO. The client then pulls one document to read the whole
 * list, rather than enumerating a directory of per-entry documents.
 *
 * The list is written in-process, directly against the object store — never over
 * HTTP — so the target collection can be configured `pullOnly: true` to reject
 * every *client* write while still being populated here. That `pullOnly` + this
 * plugin is how a target list becomes "owned by the indexer": clients read it,
 * but only the projection writes it.
 *
 * Concurrency: many source writes can target the same list document at once, so
 * each apply is a CAS loop — pull the current list, fold the entry in, then
 * `push` with the pulled `baseHash`. `push` rejects on a stale hash
 * (optimistic-concurrency), so on conflict we re-pull and re-apply onto fresh
 * state rather than clobbering a concurrent write. The pull MUST happen inside
 * the loop so each retry sees the latest list. Failures are logged, never thrown
 * — `afterWrite` must not break the originating client write (same contract as
 * starfish-queuing).
 *
 * Scale: every write rewrites and re-hashes the whole list document under one
 * per-key lock, and in-process pushes bypass the HTTP `maxBodyBytes` limit, so a
 * single list can grow unbounded server-side. Keep lists bounded — shard via a
 * `target` function (one list per tenant/bucket) and/or set `maxItems`.
 */

import type { ServerPlugin, WriteEvent } from "@drakkar.software/starfish-protocol"
import {
  pull,
  push,
  type ObjectStore,
  type StoreContext,
} from "@drakkar.software/starfish-server"
import type { Projection, ProjectionItem, ProjectionOp } from "./config.js"

export interface ProjectionPluginOptions {
  /** Object store the lists are written to (same store the router uses). */
  store: ObjectStore
  /** The lists to maintain. Each `source` collection's writes drive its `project`. */
  projections: Projection[]
  /** Max CAS attempts when concurrent writes keep changing a list under us.
   *  On exhaustion the op is logged and dropped. Default 8. */
  maxRetries?: number
  /** Optional soft cap on entries per list. When appending would exceed it the
   *  op is logged and dropped (existing entries are never evicted). Unbounded by
   *  default — prefer sharding via a `target` function for large views. */
  maxItems?: number
}

const DEFAULT_MAX_RETRIES = 8

/** Normalize a projection's `source` to a set for O(1) membership checks. */
function sourceSet(source: string | string[]): Set<string> {
  return new Set(Array.isArray(source) ? source : [source])
}

function resolveTarget(target: Projection["target"], event: WriteEvent): string | null {
  return typeof target === "function" ? target(event) : target
}

/**
 * Build a `ServerPlugin` that maintains one or more projection lists: after a
 * successful push to a watched `source` collection, it derives an entry op via
 * the app's `project` function and folds it into the target list document.
 */
export function createProjectionServerPlugin(opts: ProjectionPluginOptions): ServerPlugin {
  const { store, projections } = opts
  const maxRetries = opts.maxRetries ?? DEFAULT_MAX_RETRIES
  const maxItems = opts.maxItems
  const compiled = projections.map((p) => ({
    sources: sourceSet(p.source),
    target: p.target,
    project: p.project,
  }))

  return {
    name: "starfish-projection",
    afterWrite: async (event: WriteEvent): Promise<void> => {
      for (const { sources, target, project } of compiled) {
        if (!sources.has(event.collection)) continue
        try {
          // Resolve the target list before running the mapping; null = ignore.
          const targetKey = resolveTarget(target, event)
          if (targetKey == null) continue
          const op = await project(event)
          if (op == null) continue
          await applyOp(store, targetKey, op, maxRetries, maxItems, event.collection)
        } catch (e) {
          // A projection failure must not break the originating client write.
          console.warn(`[Starfish] projection for "${event.collection}" failed:`, e)
        }
      }
    },
  }
}

/** Fold a single entry op into the target list document under a CAS retry loop. */
async function applyOp(
  store: ObjectStore,
  targetKey: string,
  op: NonNullable<ProjectionOp>,
  maxRetries: number,
  maxItems: number | undefined,
  sourceCollection: string,
): Promise<void> {
  // A projection-owned write runs in-process with the plugin's authority, not a
  // client's — no per-document role gating.
  const ctx: StoreContext = {
    collection: sourceCollection,
    params: {},
    identity: null,
    roles: [],
    action: "push",
  }

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    // Re-pull every iteration so each retry folds onto the latest list.
    const current = await pull(store, targetKey, ctx)
    const baseHash = current.hash || null
    const stored = (current.data as { items?: unknown }).items
    const items: ProjectionItem[] = Array.isArray(stored) ? [...(stored as ProjectionItem[])] : []
    const idx = items.findIndex((it) => it.id === op.id)

    if (op.remove === true) {
      if (idx === -1) return // already absent — nothing to write
      items.splice(idx, 1)
    } else if (idx === -1) {
      if (maxItems != null && items.length >= maxItems) {
        console.warn(
          `[Starfish] projection list "${targetKey}" at maxItems=${maxItems}; dropping append of id "${op.id}"`,
        )
        return
      }
      items.push({ id: op.id, value: op.value })
    } else {
      // Update in place: keep the entry's position, full-replace its value.
      items[idx] = { id: op.id, value: op.value }
    }

    const result = await push(store, targetKey, { items }, baseHash, undefined, false, false, undefined, ctx)
    if (!("error" in result)) return // PushSuccess — done
    // hash_mismatch: a concurrent write changed the list; loop to re-pull/re-apply.
  }

  console.warn(
    `[Starfish] projection list "${targetKey}" exhausted ${maxRetries} CAS retries; dropped op for id "${op.id}"`,
  )
}
