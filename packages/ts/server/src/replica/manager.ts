import { deepMerge, computeHash } from "@starfish/protocol"
import type { AbstractObjectStore } from "../storage/base.js"
import type { CollectionConfig } from "../config/schema.js"
import { pull } from "../protocol/pull.js"
import { push } from "../protocol/push.js"
import { isPushConflict } from "../protocol/types.js"

export class ReplicaManager {
  private readonly store: AbstractObjectStore
  private readonly collections: CollectionConfig[]
  private readonly selfBaseUrl?: string
  private readonly onError?: (error: Error) => void
  private lastHashes = new Map<string, string>()
  private lastSyncTime = new Map<string, number>()
  private intervals: ReturnType<typeof setInterval>[] = []

  constructor(opts: {
    store: AbstractObjectStore
    collections: CollectionConfig[]
    selfBaseUrl?: string
    onError?: (error: Error) => void
  }) {
    this.store = opts.store
    this.collections = opts.collections.filter((c) => c.remote)
    this.selfBaseUrl = opts.selfBaseUrl
    this.onError = opts.onError
  }

  async start(): Promise<void> {
    for (const col of this.collections) {
      const remote = col.remote!
      if (remote.intervalMs && remote.intervalMs > 0) {
        const interval = setInterval(() => {
          this.syncNow(col.name).catch((err) => this.onError?.(err as Error))
        }, remote.intervalMs)
        this.intervals.push(interval)
      }
      await this.syncNow(col.name).catch((err) => this.onError?.(err as Error))
    }
  }

  async stop(): Promise<void> {
    for (const interval of this.intervals) {
      clearInterval(interval)
    }
    this.intervals = []
  }

  async onNotification(collectionName: string): Promise<void> {
    await this.syncNow(collectionName)
  }

  async onPull(collectionName: string): Promise<void> {
    const col = this.collections.find((c) => c.name === collectionName)
    if (!col?.remote) return

    const triggers = col.remote.syncTriggers ?? []
    if (!triggers.includes("on_pull")) return

    const minInterval = col.remote.onPullMinIntervalMs ?? 0
    const lastSync = this.lastSyncTime.get(collectionName) ?? 0
    if (Date.now() - lastSync < minInterval) return

    await this.syncNow(collectionName)
  }

  async syncNow(name: string): Promise<void> {
    const col = this.collections.find((c) => c.name === name)
    if (!col?.remote) return

    const remote = col.remote
    const pullUrl = `${remote.url.replace(/\/$/, "")}${remote.pullPath}`

    const headers: Record<string, string> = {
      Accept: "application/json",
      ...(remote.headers ?? {}),
    }

    const resp = await fetch(pullUrl, { headers })
    if (!resp.ok) {
      throw new Error(`Remote pull failed: ${resp.status}`)
    }

    const remoteResult = (await resp.json()) as {
      data: Record<string, unknown>
      hash: string
      timestamp: number
    }

    const lastHash = this.lastHashes.get(name) ?? ""
    if (remoteResult.hash === lastHash) return

    const writeMode = remote.writeMode ?? "pull_only"

    if (writeMode === "bidirectional") {
      const localResult = await pull(this.store, col.storagePath)
      if (localResult.hash && localResult.hash !== remoteResult.hash) {
        const merged = deepMerge(localResult.data, remoteResult.data)
        const result = await push(this.store, col.storagePath, merged, localResult.hash)
        if (!isPushConflict(result)) {
          this.lastHashes.set(name, result.hash)
        }
      } else {
        const result = await push(
          this.store,
          col.storagePath,
          remoteResult.data,
          localResult.hash || null,
        )
        if (!isPushConflict(result)) {
          this.lastHashes.set(name, result.hash)
        }
      }
    } else {
      const localResult = await pull(this.store, col.storagePath)
      const result = await push(
        this.store,
        col.storagePath,
        remoteResult.data,
        localResult.hash || null,
      )
      if (!isPushConflict(result)) {
        this.lastHashes.set(name, result.hash)
      }
    }

    this.lastSyncTime.set(name, Date.now())
  }

  async syncAll(): Promise<void> {
    await Promise.allSettled(
      this.collections.map((col) =>
        this.syncNow(col.name).catch((err) => this.onError?.(err as Error)),
      ),
    )
  }
}
