/**
 * Server plugin for the replication extension.
 *
 * Implements the route hooks from the `ServerPlugin` contract:
 * - `beforePull`: rejects pulls on write-only (`push_only`) collections, and
 *   triggers a sync from the primary when the `on_pull` trigger is configured.
 * - `interceptPush`: rejects pushes on read-only (`pull_only`) collections, and
 *   proxies the push to the primary when the write mode is `push_through`.
 * - `shutdown`: stops the manager's scheduled timers.
 *
 * Like `starfish-queuing`, this plugin owns its config: apps pass a
 * `{ [collectionName]: RemoteConfig }` map; the field is no longer part of the
 * core `CollectionConfig`. The factory validates the config at construction
 * and throws on conflict.
 */

import type {
  ServerPlugin,
  PullHookContext,
  PullHookResult,
  PushHookContext,
  PushHookResult,
} from "@drakkar.software/starfish-protocol"
import type { ObjectStore, SyncConfig } from "@drakkar.software/starfish-server"
import { ReplicaManager } from "./manager.js"
import type { RemoteCollection, RemoteConfig } from "./config.js"
import { validateReplicaConfig } from "./validate.js"

export interface ReplicaPluginOptions {
  /** Store the replica reads/writes local documents in. */
  store: ObjectStore
  /** The server's sync config (used to resolve storage paths + validate). */
  syncConfig: SyncConfig
  /** Per-collection remote config, keyed by root collection name. */
  collections: Record<string, RemoteConfig>
  /** Override `fetch` (e.g. in tests). */
  fetchFn?: typeof fetch
  /** Called when a background sync fails. */
  onError?: (name: string, error: Error) => void
}

/** A `ServerPlugin` that also exposes its `ReplicaManager` so the app can
 *  start the scheduled/initial syncs (`manager.start()`). */
export interface ReplicaServerPlugin extends ServerPlugin {
  manager: ReplicaManager
}

export function createReplicaServerPlugin(opts: ReplicaPluginOptions): ReplicaServerPlugin {
  const { store, syncConfig, collections, fetchFn, onError } = opts

  const errors = validateReplicaConfig(syncConfig, collections)
  if (errors.length > 0) {
    throw new Error(
      `[starfish-replica] invalid configuration:\n- ${errors.join("\n- ")}`,
    )
  }

  // Resolve each remote collection's static storage path from the sync config.
  const byName = new Map(syncConfig.collections.map((c) => [c.name, c]))
  const remoteCols: RemoteCollection[] = Object.entries(collections).map(
    ([name, remote]) => ({
      name,
      storagePath: byName.get(name)!.storagePath,
      remote,
    }),
  )

  const manager = new ReplicaManager(store, remoteCols, { fetchFn, onError })

  return {
    name: "starfish-replica",
    manager,
    beforePull: (ctx: PullHookContext): PullHookResult | Promise<PullHookResult> => {
      const remote = manager.remoteFor(ctx.collection)
      if (!remote) return { action: "proceed" }
      if (remote.writeMode === "push_only") {
        return { action: "reject", status: 405, error: "This collection is write-only on this server" }
      }
      if (remote.syncTriggers.includes("on_pull")) {
        return manager.onPull(ctx.collection).then(() => ({ action: "proceed" as const }))
      }
      return { action: "proceed" }
    },
    interceptPush: async (ctx: PushHookContext): Promise<PushHookResult> => {
      const remote = manager.remoteFor(ctx.collection)
      if (!remote) return { action: "proceed" }
      if (remote.writeMode === "pull_only") {
        return { action: "reject", status: 405, error: "This collection is read-only on this server" }
      }
      if (remote.writeMode === "push_through") {
        const { status, body } = await manager.proxyPush(ctx.collection, ctx.rawBody)
        return { action: "respond", status, body }
      }
      // bidirectional / push_only → store locally, then sync reconciles
      return { action: "proceed" }
    },
    shutdown: () => manager.stop(),
  }
}
