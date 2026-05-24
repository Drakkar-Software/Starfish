import type { ObjectStore, PushSuccess } from "@drakkar.software/starfish-server"
import { push, deepSanitize } from "@drakkar.software/starfish-server"
import { deepMerge } from "@drakkar.software/starfish-protocol"
import type { RemoteCollection, RemoteConfig } from "./config.js"

export class ReplicaManager {
  private _store: ObjectStore
  private _remoteCols: RemoteCollection[]
  private _fetch: typeof fetch
  private _onError: (name: string, error: Error) => void
  private _lastHash = new Map<string, string>()
  private _lastSyncAt = new Map<string, number>()
  private _timers: ReturnType<typeof setInterval>[] = []

  constructor(
    store: ObjectStore,
    collections: RemoteCollection[],
    opts?: {
      fetchFn?: typeof fetch
      onError?: (name: string, error: Error) => void
    },
  ) {
    this._store = store
    this._remoteCols = collections
    this._fetch = opts?.fetchFn ?? globalThis.fetch.bind(globalThis)
    this._onError =
      opts?.onError ??
      ((name, err) => console.error(`[ReplicaManager] ${name}: ${err}`))
  }

  /** The `RemoteConfig` for a collection name, or `undefined` if not replicated. */
  remoteFor(name: string): RemoteConfig | undefined {
    return this._find(name)?.remote
  }

  start(): void {
    for (const col of this._remoteCols) {
      const remote = col.remote
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

    const minIntervalMs = col.remote.onPullMinIntervalMs
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

  /**
   * Forward a client push to the primary (write_mode `push_through`). Returns
   * the response status + body to relay to the client. On success, triggers a
   * background sync so the local replica catches up. Framework-neutral — the
   * caller (replica plugin) turns this into an HTTP response.
   */
  async proxyPush(
    name: string,
    rawBody: string,
  ): Promise<{ status: number; body: unknown }> {
    const col = this._find(name)
    if (!col) {
      return { status: 404, body: { error: `Unknown remote collection: "${name}"` } }
    }
    const remote = col.remote
    const primaryUrl = `${remote.url.replace(/\/+$/, "")}${remote.pushPath}`
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...remote.headers,
    }

    try {
      const resp = await this._fetch(primaryUrl, {
        method: "POST",
        body: rawBody,
        headers,
      })

      if (resp.status === 409) {
        return { status: 409, body: { error: "hash_mismatch" } }
      }
      if (!resp.ok) {
        return { status: resp.status, body: { error: `Primary returned ${resp.status}` } }
      }

      const body = (await resp.json()) as Record<string, unknown>

      // Validate the primary's response shape before relaying it to our client.
      // A successful push returns `{ hash, timestamp }`; refuse to forward an
      // arbitrary/garbage body a compromised or misbehaving primary might send.
      if (
        typeof body !== "object" ||
        body === null ||
        Array.isArray(body) ||
        typeof body["hash"] !== "string"
      ) {
        console.error(`[Starfish] Primary returned an unexpected push response shape for "${name}"`)
        return { status: 502, body: { error: "Primary returned an unexpected response" } }
      }

      // Trigger sync in background (don't await)
      this.syncNow(name).catch((e) => {
        console.error(`[Starfish] Background sync failed for "${name}" after proxy push:`, e)
      })

      return { status: resp.status, body }
    } catch (e) {
      console.error(`[Starfish] Failed to reach primary for "${name}":`, e)
      return { status: 502, body: { error: "Failed to reach primary" } }
    }
  }

  private _find(name: string): RemoteCollection | undefined {
    return this._remoteCols.find((c) => c.name === name)
  }

  private async _syncSafe(col: RemoteCollection): Promise<void> {
    try {
      await this._doSync(col)
    } catch (e) {
      this._onError(col.name, e instanceof Error ? e : new Error(String(e)))
    }
  }

  private async _doSync(col: RemoteCollection): Promise<void> {
    const remote = col.remote

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

    // Strip prototype-pollution keys before writing primary data into the local
    // store. The bidirectional merge above already drops them via deepMerge, but
    // the pull-only / push-through path writes the primary's `data` verbatim and
    // must not trust it — a compromised primary could otherwise plant a
    // `__proto__` / `constructor` payload.
    const sanitized = deepSanitize(dataToWrite) as Record<string, unknown>

    // Use currentLocalHash directly ("" works for both "no document" and "corrupt
    // document"): push() treats baseHash="" the same as no hash when the stored
    // currentHash is also "". Must NOT coerce "" → null — push() rejects
    // baseHash=null when a (corrupt) doc is present, which would leave a corrupt
    // local doc permanently unrecoverable (sync would throw "Concurrent write"
    // forever). A valid local doc still yields its real hash, so genuine
    // concurrent-write detection is preserved.
    const baseHash: string = currentLocalHash
    const result = await push(this._store, documentKey, sanitized, baseHash)

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
