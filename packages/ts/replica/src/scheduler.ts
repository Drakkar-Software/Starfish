import type { ChannelSchedule, ReplicaChannel, ScheduledChannel } from "./channel.js"
import { REPLICATOR_CTX } from "./channel.js"

export interface ChannelSchedulerEntry {
  channel: ReplicaChannel
  schedule: ChannelSchedule
}

export function defaultSchedulerOnError(name: string, err: Error): void {
  console.error(`[ReplicaManager] ${name}: ${err}`)
}

/** Fallback interval for a `"scheduled"` entry whose schedule omits `intervalMs`. */
const DEFAULT_INTERVAL_MS = 60_000

/**
 * Pure scheduler over an arbitrary set of `ReplicaChannel`s: interval loop,
 * on_pull cooldown, error funnel. Deliberately has NO knowledge of HTTP,
 * local storage, or Starfish spaces, and does NOT import `./http-channel.js`
 * — so importing this class never pulls in `@drakkar.software/starfish-server`.
 *
 * `ReplicaManager` (../manager.js) EXTENDS this and adds the back-compat
 * HTTP constructor (`new ReplicaManager(store, collections, opts)`) plus
 * `remoteFor`/`proxyPush` — importing THAT class always drags in
 * `starfish-server`, because its legacy constructor statically needs
 * `HttpReplicaChannel` to build channels from `RemoteCollection[]`.
 * `./space`'s own `ReplicaManager` re-export IS this class directly (see
 * `./space/index.js`) — safe to bundle into a mobile/browser client that
 * only ever drives `SpaceMirrorChannel`s.
 */
export class ChannelScheduler {
  protected _entries: ChannelSchedulerEntry[]
  protected _onError: (name: string, error: Error) => void
  private _lastSyncAt = new Map<string, number>()
  private _timers: ReturnType<typeof setInterval>[] = []

  constructor(
    entries: ScheduledChannel[],
    opts?: { onError?: (name: string, error: Error) => void },
  ) {
    this._entries = entries.map((e) => ({ channel: e.channel, schedule: e.schedule }))
    this._onError = opts?.onError ?? defaultSchedulerOnError
  }

  start(): void {
    for (const entry of this._entries) {
      if (entry.schedule.triggers.includes("scheduled")) {
        // Initial sync
        this._syncSafe(entry)
        // Scheduled loop
        // `ChannelSchedule.intervalMs` is optional (unlike `RemoteCollection`'s,
        // which is required), so a hand-built schedule can omit it — and a `0`
        // fallback would spin an unthrottled sync loop against the network
        // rather than doing nothing visible. Default to a minute, matching
        // Python's `scheduler.py` (`interval_ms or 60_000`).
        const timer = setInterval(
          () => this._syncSafe(entry),
          entry.schedule.intervalMs ?? DEFAULT_INTERVAL_MS,
        )
        this._timers.push(timer)
      } else {
        this._syncSafe(entry)
      }
    }
  }

  stop(): void {
    for (const timer of this._timers) {
      clearInterval(timer)
    }
    this._timers = []
  }

  async onPull(name: string): Promise<void> {
    const entry = this._find(name)
    if (!entry) return

    const minIntervalMs = entry.schedule.onPullMinIntervalMs
    if (minIntervalMs != null) {
      const last = this._lastSyncAt.get(name)
      if (last != null && performance.now() - last < minIntervalMs) {
        return // within cooldown
      }
    }

    await this._syncSafe(entry)
  }

  async syncNow(name: string): Promise<void> {
    const entry = this._find(name)
    if (!entry) {
      throw new Error(`[ReplicaManager] Unknown remote collection: "${name}"`)
    }
    await this._doSync(entry)
  }

  async syncAll(): Promise<void> {
    await Promise.all(this._entries.map((entry) => this._syncSafe(entry)))
  }

  protected _find(name: string): ChannelSchedulerEntry | undefined {
    return this._entries.find((e) => e.channel.name === name)
  }

  protected async _syncSafe(entry: ChannelSchedulerEntry): Promise<void> {
    try {
      await this._doSync(entry)
    } catch (e) {
      this._onError(entry.channel.name, e instanceof Error ? e : new Error(String(e)))
    }
  }

  protected async _doSync(entry: ChannelSchedulerEntry): Promise<void> {
    await entry.channel.sync(REPLICATOR_CTX)
    // Stamp on every COMPLETED sync (not just one that wrote something) — a
    // no-op sync (hash unchanged) still means we just checked the primary, so
    // the on_pull cooldown should apply to it too.
    this._lastSyncAt.set(entry.channel.name, performance.now())
  }
}
