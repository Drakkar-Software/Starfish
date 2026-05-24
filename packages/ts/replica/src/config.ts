/**
 * Replica configuration types. Owned by the replica plugin — apps pass a
 * `{ [collectionName]: RemoteConfig }` map to `createReplicaServerPlugin`.
 *
 * (Moved out of `starfish-server`'s `CollectionConfig` so the core schema no
 * longer knows about replication — mirrors how `QueueConfig` lives in
 * `starfish-queuing`.)
 */

/** How local client writes are handled on a replica collection. */
export type WriteMode = "pull_only" | "push_through" | "bidirectional" | "push_only"

/** Events that trigger a sync from the primary. */
export type SyncTrigger = "scheduled" | "on_pull"

/**
 * Declares that a collection should be replicated from a remote (primary)
 * starfish server. All replica behavior is fully described here.
 */
export interface RemoteConfig {
  /** Base URL of the primary starfish server, e.g. `https://primary.example.com/v1`. */
  url: string
  /** Pull endpoint path on the primary, e.g. `/pull/posts/featured`. Static — no template vars. */
  pullPath: string
  /** Push endpoint path on the primary. Required for `push_through`/`bidirectional`. */
  pushPath?: string
  /** Sync interval in ms (used by the `scheduled` trigger). */
  intervalMs: number
  /** Static HTTP headers sent to the primary on every request (e.g. `Authorization`). */
  headers: Record<string, string>
  /** How local client writes are handled. */
  writeMode: WriteMode
  /** Which events trigger a sync from the primary. */
  syncTriggers: SyncTrigger[]
  /** Minimum ms between two `on_pull`-triggered syncs (cooldown). */
  onPullMinIntervalMs?: number
}

/**
 * A collection to replicate: the manager needs its name (route key), its
 * static storage path (document key), and its `RemoteConfig`.
 */
export interface RemoteCollection {
  name: string
  storagePath: string
  remote: RemoteConfig
}
