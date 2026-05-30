/**
 * Server plugin for the projection (materialized-view) extension.
 *
 * Implements the `afterWrite` write-path hook from the `ServerPlugin` contract:
 * after a successful push the server hands the plugin a `WriteEvent`; for any
 * projection whose `source` includes the event's collection, the plugin runs the
 * app-supplied pure `project(event)` mapping and applies its outcome to the
 * `store` — UPSERT (`{ key, data }`), DELETE (`{ key, delete: true }`), or IGNORE
 * (`null`). The app supplies only the mapping; the plugin owns all store IO.
 *
 * The view is written in-process, directly against the object store — never over
 * HTTP — so the target collection can be configured `pullOnly: true` to reject
 * every *client* write while still being populated here. That `pullOnly` + this
 * plugin is how a target view becomes "owned by the indexer": clients can read
 * and (if `listable`) enumerate it, but only the projection writes it.
 *
 * Writes use the server's `push` helper, so the stored document is byte-identical
 * to a normal pushed document (same `{ v, data, ts, hash }` envelope) and the
 * pull / list-with-values / batch-pull paths read it back unchanged. Each upsert
 * reads the current hash first and passes it as `baseHash`, so a projection
 * overwrites the previous view value (last-writer-wins by key) rather than
 * conflicting. Failures are logged, never thrown — `afterWrite` must not break
 * the originating client write (same contract as starfish-queuing).
 */

import type { ServerPlugin, WriteEvent } from "@drakkar.software/starfish-protocol"
import {
  pull,
  push,
  type ObjectStore,
  type StoreContext,
} from "@drakkar.software/starfish-server"
import type { Projection } from "./config.js"

export interface ProjectionPluginOptions {
  /** Object store the materialized views are written to (same store the router uses). */
  store: ObjectStore
  /** The views to maintain. Each `source` collection's writes drive its `project`. */
  projections: Projection[]
}

/** Normalize a projection's `source` to a set for O(1) membership checks. */
function sourceSet(source: string | string[]): Set<string> {
  return new Set(Array.isArray(source) ? source : [source])
}

/**
 * Build a `ServerPlugin` that maintains one or more materialized views: after a
 * successful push to a watched `source` collection, it derives a target document
 * via the app's `project` function and upserts/deletes it in `store`.
 */
export function createProjectionServerPlugin(opts: ProjectionPluginOptions): ServerPlugin {
  const { store, projections } = opts
  const compiled = projections.map((p) => ({ sources: sourceSet(p.source), project: p.project }))

  return {
    name: "starfish-projection",
    afterWrite: async (event: WriteEvent): Promise<void> => {
      for (const { sources, project } of compiled) {
        if (!sources.has(event.collection)) continue
        try {
          const result = await project(event)
          if (result == null) continue

          // A projection-owned write carries no per-document StoreContext role
          // gating — it runs in-process with the plugin's authority, not a
          // client's. `action` reflects the underlying store operation.
          if (result.delete === true) {
            const ctx: StoreContext = {
              collection: event.collection,
              params: {},
              identity: null,
              roles: [],
              action: "delete",
            }
            await store.delete(result.key, ctx)
            continue
          }

          const ctx: StoreContext = {
            collection: event.collection,
            params: {},
            identity: null,
            roles: [],
            action: "push",
          }
          // Read the current hash so the upsert overwrites cleanly (the view is
          // last-writer-wins by key, not optimistic-concurrency controlled).
          const current = await pull(store, result.key, ctx)
          const baseHash = current.hash || null
          await push(store, result.key, result.data, baseHash, undefined, false, false, undefined, ctx)
        } catch (e) {
          // A projection failure must not break the originating client write.
          console.warn(`[Starfish] projection for "${event.collection}" failed:`, e)
        }
      }
    },
  }
}
