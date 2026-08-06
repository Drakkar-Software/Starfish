/**
 * The default `ReplicaChannel`: primary→replica-server HTTP pull, reconciled
 * against a local `starfish-server` `ObjectStore`.
 *
 * This is `ReplicaManager`'s original (pre-generalization) `_doSync`/`proxyPush`
 * bodies, moved here VERBATIM — the reconciliation logic (hash short-circuit,
 * `bidirectional` deepMerge, prototype-pollution stripping, corrupt-doc
 * recovery) is unchanged. See `ReplicaManager`'s constructor for how this
 * channel is built from a `RemoteCollection`.
 */
import type { ObjectStore, PushSuccess } from "@drakkar.software/starfish-server"
import { push, deepSanitize } from "@drakkar.software/starfish-server"
import { deepMerge } from "@drakkar.software/starfish-protocol"
import type { RemoteCollection, RemoteConfig } from "./config.js"
import type { ReplicaChannel, ReplicaCallContext } from "./channel.js"

export class HttpReplicaChannel implements ReplicaChannel {
  readonly name: string
  readonly remote: RemoteConfig
  private _store: ObjectStore
  private _storagePath: string
  private _fetch: typeof fetch
  private _lastHash: string | undefined

  constructor(store: ObjectStore, col: RemoteCollection, fetchFn: typeof fetch) {
    this.name = col.name
    this.remote = col.remote
    this._store = store
    this._storagePath = col.storagePath
    this._fetch = fetchFn
  }

  async sync(_ctx: ReplicaCallContext): Promise<void> {
    const remote = this.remote

    if (remote.writeMode === "push_only") return

    const documentKey = this._storagePath
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

    if (this._lastHash === primaryHash) return

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
      this._lastHash = primaryHash
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
        `[ReplicaManager] Concurrent write on "${this.name}" — will retry`,
      )
    }

    const success = result as PushSuccess
    this._lastHash = success.hash
  }

  /**
   * Forward a client push to the primary (write_mode `push_through`). Returns
   * the response status + body to relay to the client. `onSuccess` is called
   * (not awaited) right before returning a successful response — the manager
   * uses it to trigger a background `syncNow` so `_lastSyncAt`/cooldown state
   * stays owned by the manager, not this channel. Framework-neutral — the
   * caller (replica plugin) turns this into an HTTP response.
   */
  async proxyPush(
    rawBody: string,
    onSuccess?: () => void,
  ): Promise<{ status: number; body: unknown }> {
    const remote = this.remote
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
        console.error(`[Starfish] Primary returned an unexpected push response shape for "${this.name}"`)
        return { status: 502, body: { error: "Primary returned an unexpected response" } }
      }

      onSuccess?.()

      return { status: resp.status, body }
    } catch (e) {
      console.error(`[Starfish] Failed to reach primary for "${this.name}":`, e)
      return { status: 502, body: { error: "Failed to reach primary" } }
    }
  }
}
