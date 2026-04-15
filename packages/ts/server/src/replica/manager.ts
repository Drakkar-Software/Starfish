import type { ObjectStore } from "../storage/base.js"
import type { CollectionConfig } from "../config/schema.js"
import type { PushSuccess } from "../protocol/types.js"
import { push } from "../protocol/push.js"
import { deepMerge } from "@drakkar.software/starfish-protocol"

export class ReplicaManager {
  private _store: ObjectStore
  private _remoteCols: CollectionConfig[]
  private _fetch: typeof fetch
  private _onError: (name: string, error: Error) => void
  private _lastHash = new Map<string, string>()
  private _lastSyncAt = new Map<string, number>()
  private _timers: ReturnType<typeof setInterval>[] = []

  constructor(
    store: ObjectStore,
    collections: CollectionConfig[],
    opts?: {
      fetchFn?: typeof fetch
      onError?: (name: string, error: Error) => void
    },
  ) {
    this._store = store
    this._remoteCols = collections.filter((c) => c.remote != null)
    this._fetch = opts?.fetchFn ?? globalThis.fetch.bind(globalThis)
    this._onError =
      opts?.onError ??
      ((name, err) => console.error(`[ReplicaManager] ${name}: ${err}`))
  }

  start(): void {
    for (const col of this._remoteCols) {
      const remote = col.remote!
      if (remote.syncTriggers.includes("scheduled")) {
        // Initial sync
        this._syncSafe(col)
        // Scheduled loop
        const timer = setInterval(
          () => this._syncSafe(col),
          remote.intervalMs,
        )
        this._timers.push(timer)
      } else {
        this._syncSafe(col)
      }
    }
  }

  stop(): void {
    for (const timer of this._timers) {
      clearInterval(timer)
    }
    this._timers = []
  }

  async onPull(collectionName: string): Promise<void> {
    const col = this._find(collectionName)
    if (!col) return

    const minIntervalMs = col.remote?.onPullMinIntervalMs
    if (minIntervalMs != null) {
      const last = this._lastSyncAt.get(collectionName)
      if (last != null && performance.now() - last < minIntervalMs) {
        return // within cooldown
      }
    }

    await this._syncSafe(col)
  }

  async syncNow(name: string): Promise<void> {
    const col = this._find(name)
    if (!col) {
      throw new Error(`[ReplicaManager] Unknown remote collection: "${name}"`)
    }
    await this._doSync(col)
  }

  async syncAll(): Promise<void> {
    await Promise.all(this._remoteCols.map((col) => this._syncSafe(col)))
  }

  private _find(name: string): CollectionConfig | undefined {
    return this._remoteCols.find((c) => c.name === name)
  }

  private async _syncSafe(col: CollectionConfig): Promise<void> {
    try {
      await this._doSync(col)
    } catch (e) {
      this._onError(col.name, e instanceof Error ? e : new Error(String(e)))
    }
  }

  private async _doSync(col: CollectionConfig): Promise<void> {
    const remote = col.remote!

    if (remote.writeMode === "push_only") return

    const documentKey = col.storagePath
    const primaryUrl = `${remote.url.replace(/\/+$/, "")}${remote.pullPath}`

    const resp = await this._fetch(primaryUrl, {
      headers: { Accept: "application/json", ...remote.headers },
    })
    if (!resp.ok) {
      throw new Error(`Primary returned ${resp.status}`)
    }
    const pulled = (await resp.json()) as Record<string, unknown>

    const primaryHash = (pulled["hash"] as string) ?? ""
    const primaryData = (pulled["data"] as Record<string, unknown>) ?? {}

    if (!primaryHash) return

    if (this._lastHash.get(col.name) === primaryHash) return

    const rawLocal = await this._store.getString(documentKey)
    let currentLocalHash = ""
    let currentLocalData: Record<string, unknown> = {}
    if (rawLocal) {
      try {
        const localDoc = JSON.parse(rawLocal) as Record<string, unknown>
        currentLocalHash = (localDoc["hash"] as string) ?? ""
        currentLocalData = (localDoc["data"] as Record<string, unknown>) ?? {}
      } catch (e) {
        console.error(`[ReplicaManager] Corrupt local document at "${documentKey}" — treating as empty:`, e)
        // currentLocalHash stays "" — push with baseHash="" matches the "" stored by push.ts on corrupt read
      }
    }

    if (currentLocalHash === primaryHash) {
      this._lastHash.set(col.name, primaryHash)
      return
    }

    let dataToWrite: Record<string, unknown>
    if (
      remote.writeMode === "bidirectional" &&
      Object.keys(currentLocalData).length > 0
    ) {
      dataToWrite = deepMerge(currentLocalData, primaryData)
    } else {
      dataToWrite = primaryData
    }

    // Use currentLocalHash directly ("" works for both "no document" and "corrupt document"):
    // push() treats baseHash="" the same as no hash when stored currentHash is also ""
    const baseHash = currentLocalHash || null
    const result = await push(this._store, documentKey, dataToWrite, baseHash)

    if (!("hash" in result)) {
      throw new Error(
        `[ReplicaManager] Concurrent write on "${col.name}" — will retry`,
      )
    }

    const success = result as PushSuccess
    this._lastHash.set(col.name, success.hash)
    this._lastSyncAt.set(col.name, performance.now())
  }
}
