import type { ObjectStore } from "@drakkar.software/starfish-server"
import type { RemoteCollection, RemoteConfig } from "./config.js"
import type { ChannelSchedule, ScheduledChannel } from "./channel.js"
import { ChannelScheduler, type ChannelSchedulerEntry } from "./scheduler.js"
import { HttpReplicaChannel } from "./http-channel.js"

function scheduleFromRemote(remote: RemoteConfig): ChannelSchedule {
  return {
    intervalMs: remote.intervalMs,
    triggers: remote.syncTriggers,
    onPullMinIntervalMs: remote.onPullMinIntervalMs,
  }
}

/**
 * `ChannelScheduler` (./scheduler.js) plus the HTTP constructor and the two
 * HTTP-only methods (`remoteFor`, `proxyPush`). Importing THIS
 * class always pulls in `@drakkar.software/starfish-server` (via
 * `HttpReplicaChannel`) — a pure `./space` consumer that never needs the
 * HTTP path should import `ReplicaManager` from `./space/index.js` instead,
 * which is `ChannelScheduler` directly and never touches `starfish-server`.
 */
export class ReplicaManager extends ChannelScheduler {
  constructor(
    store: ObjectStore,
    collections: RemoteCollection[],
    opts?: {
      fetchFn?: typeof fetch
      onError?: (name: string, error: Error) => void
    },
  ) {
    const fetchFn = opts?.fetchFn ?? globalThis.fetch.bind(globalThis)
    const entries: ScheduledChannel[] = collections.map((col) => ({
      channel: new HttpReplicaChannel(store, col, fetchFn),
      schedule: scheduleFromRemote(col.remote),
    }))
    super(entries, { onError: opts?.onError })
  }

  /** The `RemoteConfig` for a collection name, or `undefined` if it isn't
   *  backed by an `HttpReplicaChannel` (e.g. not found, or a space channel). */
  remoteFor(name: string): RemoteConfig | undefined {
    const entry = this._find(name)
    return entry && entry.channel instanceof HttpReplicaChannel ? entry.channel.remote : undefined
  }

  /**
   * Forward a client push to the primary (write_mode `push_through`). Only
   * meaningful for an `HttpReplicaChannel`-backed collection — returns 404
   * otherwise. See `HttpReplicaChannel.proxyPush` for the HTTP mechanics; this
   * method owns triggering + timestamping the follow-up background sync so
   * scheduling state stays a manager concern.
   */
  async proxyPush(
    name: string,
    rawBody: string,
  ): Promise<{ status: number; body: unknown }> {
    const entry = this._find(name)
    if (!entry || !(entry.channel instanceof HttpReplicaChannel)) {
      return { status: 404, body: { error: `Unknown remote collection: "${name}"` } }
    }
    return entry.channel.proxyPush(rawBody, () => {
      // Trigger sync in background (don't await)
      this.syncNow(name).catch((e) => {
        console.error(`[Starfish] Background sync failed for "${name}" after proxy push:`, e)
      })
    })
  }
}

export type { ChannelSchedulerEntry }
