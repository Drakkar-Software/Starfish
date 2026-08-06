/**
 * The pluggable data-path seam `ReplicaManager` schedules against.
 *
 * `ReplicaManager` owns ONLY scheduling (interval loop, on_pull cooldown,
 * error funnel) — it knows nothing about HTTP, local storage, or Starfish
 * spaces. Each `ReplicaChannel` owns one collection's actual sync mechanics
 * behind a single `sync()` seam. `HttpReplicaChannel` (../http-channel.ts) is
 * the default, unchanged primary→replica-server path; `SpaceMirrorChannel`
 * (./space/mirror-channel.ts) is a second, independent implementation that
 * writes into a Starfish space instead.
 */
import type { SyncTrigger } from "./config.js"

export type { SyncTrigger }

/**
 * Passed into `ReplicaChannel.sync()` on every invocation.
 *
 * `callKind` distinguishes a replication-driven call (scheduled / on_pull /
 * syncNow / syncAll, always `"replicator"`) from a direct app call a channel
 * implementation may also expose (`"classic"`) — so one shared data-access
 * function on the app side can serve both call sites and branch on which one
 * this is, without the channel/manager needing to know why.
 */
export interface ReplicaCallContext {
  callKind: "replicator" | "classic"
  /** Optional cancellation signal a caller may pass to a long-running sync. */
  signal?: AbortSignal
}

/** The context `ReplicaManager` passes on every scheduling-driven call. */
export const REPLICATOR_CTX: ReplicaCallContext = { callKind: "replicator" }

/**
 * One collection's sync mechanics. `name` is the route key `ReplicaManager`
 * looks channels up by (matches `RemoteCollection.name` for the HTTP path).
 */
export interface ReplicaChannel {
  readonly name: string
  sync(ctx: ReplicaCallContext): Promise<void>
}

/** When/how often `ReplicaManager` drives a channel's `sync()`. */
export interface ChannelSchedule {
  /** Interval in ms for the `"scheduled"` trigger. Ignored otherwise. */
  intervalMs?: number
  /** Which events trigger a sync. */
  triggers: SyncTrigger[]
  /** Minimum ms between two `on_pull`-triggered syncs (cooldown). */
  onPullMinIntervalMs?: number
}

/** A channel plus the schedule `ReplicaManager` should drive it on. */
export interface ScheduledChannel {
  channel: ReplicaChannel
  schedule: ChannelSchedule
}
