/**
 * Generic per-identity preference store, persisted on the user's `_spaces`
 * registry doc as one app-specific `extra` field (see {@link updateSpacesExtraField}).
 *
 * This factors the shared machinery every "preference" feature needs — an
 * in-memory cache with change subscriptions, KV persistence (via the
 * `kvAdapter` installed through {@link configureSpaces}), server hydration with
 * a caller-supplied merge, and a CAS-safe synced write — so a consuming app only
 * supplies configuration (field name, empty value, coerce/merge functions, KV
 * key) plus its own domain accessors.
 *
 * Two write cadences are supported from one config:
 *  - **write-through** (default): each {@link PrefsStore.mutate} pushes to the
 *    server immediately, applying the same per-operation function to the server's
 *    current value. Use for low-frequency toggles (e.g. mutes).
 *  - **debounced** (set `flushDelayMs`): {@link PrefsStore.mutate} batches, then
 *    flushes the whole cache snapshot through `merge`. Use for high-frequency
 *    updates (e.g. read marks).
 *
 * NOTE: the in-flight guard on {@link PrefsStore.hydrate} covers the write-through
 * server round-trip, but NOT the debounce window (the timer is pending with no
 * in-flight request). Debounced mode should therefore use a **monotonic** `merge`
 * (one that never drops a local key — e.g. max-merge), so a server hydrate that
 * lands mid-debounce cannot clobber a not-yet-flushed local change. Pair a
 * replace/server-wins `merge` with write-through mode.
 */
import type { StarfishClient } from "@drakkar.software/starfish-client"

import type { Session } from "./session.js"
import { updateSpacesExtraField } from "./registry.js"
import { getSpacesConfig } from "./config.js"

/** A live, subscribable preference store bound to one `_spaces` extra-field. */
export interface PrefsStore<T> {
  /** Current in-memory value. */
  get(): T
  /** Subscribe to change notifications; returns an unsubscribe function. */
  subscribe(listener: () => void): () => void
  /** Load + coerce the value from KV (primary key, then any legacy keys), merged. */
  loadFromKv(userId: string): Promise<T>
  /**
   * Fold a freshly-read server value into the cache. No-op while a local write
   * is in flight (so an optimistic change is never clobbered by a stale read).
   * When `foldKvOnHydrate` is set, KV + legacy values are folded in first.
   */
  hydrate(userId: string, serverPrefs: T): Promise<void>
  /** Clear to `empty` and drop any pending flush (e.g. on sign-out). */
  reset(): void
  /**
   * Apply a per-operation change. `apply(cur)` returns the next value, or `null`
   * when nothing changed. The optimistic result is emitted + persisted locally,
   * then synced to the server (immediately, or on the debounce flush).
   */
  mutate(session: Session, apply: (cur: T) => T | null): Promise<void>
  /** Force any pending debounced flush to run now. */
  flushNow(): Promise<void>
}

/** Configuration for {@link createPrefsStore}. */
export interface CreatePrefsStoreOptions<T> {
  /** The `_spaces` doc extra-field key this store owns (e.g. `"mutes"`, `"reads"`). */
  field: string
  /** Selects the Starfish client used for the synced registry write. */
  client: (session: Session) => StarfishClient
  /** The empty/default value. */
  empty: T
  /** Coerce a raw stored/parsed value (possibly legacy-shaped) into `T`. */
  coerce: (raw: unknown) => T
  /**
   * Merge `incoming` into `base`, returning the merged value or `null` when the
   * result is identical to `base` (no change). Used for server hydration and,
   * in debounced mode, for the synced flush.
   */
  merge: (base: T, incoming: T) => T | null
  /** Primary KV key for a userId. */
  kvKey: (userId: string) => string
  /** Optional legacy KV keys folded in on load/hydrate (back-compat migration). */
  legacyKeys?: (userId: string) => string[]
  /** When set, `mutate` debounces the server flush by this many ms. */
  flushDelayMs?: number
  /** When true, `hydrate` folds KV + legacy values in before the server value. */
  foldKvOnHydrate?: boolean
  /** Console tag for sync-error logs (e.g. `"[OctoChat]"`). */
  logTag?: string
}

/**
 * Create a {@link PrefsStore}. State is held in the returned instance's closure,
 * so it is safe to create one per app (or per test).
 */
export function createPrefsStore<T>(opts: CreatePrefsStoreOptions<T>): PrefsStore<T> {
  const { field, client, empty, coerce, merge, kvKey, legacyKeys, flushDelayMs, foldKvOnHydrate, logTag } = opts

  let cache: T = empty
  let activeKey: string | null = null
  let pending = 0
  let flushSession: Session | null = null
  let flushTimer: ReturnType<typeof setTimeout> | null = null
  const listeners = new Set<() => void>()

  // KV is read lazily so it reflects the kvAdapter active at call time (it may be
  // installed via configureSpaces after this store is created).
  const kv = () => getSpacesConfig().kvAdapter

  function emit(next: T): void {
    cache = next
    for (const l of listeners) l()
  }

  function persist(): void {
    const adapter = kv()
    if (activeKey && adapter) void adapter.setItem(activeKey, JSON.stringify(cache)).catch(() => {})
  }

  async function readKey(key: string): Promise<T | null> {
    const adapter = kv()
    if (!adapter) return null
    const raw = await adapter.getItem(key).catch(() => null)
    if (!raw) return null
    try {
      return coerce(JSON.parse(raw))
    } catch {
      return null
    }
  }

  async function loadFromKv(userId: string): Promise<T> {
    const keys = [kvKey(userId), ...(legacyKeys?.(userId) ?? [])]
    let acc = empty
    for (const key of keys) {
      const val = await readKey(key)
      if (val === null) continue
      acc = merge(acc, val) ?? acc
    }
    return acc
  }

  async function flush(): Promise<void> {
    if (flushTimer) {
      clearTimeout(flushTimer)
      flushTimer = null
    }
    const session = flushSession
    if (!session) return
    const snapshot = cache
    pending++
    try {
      await updateSpacesExtraField<T>(client(session), session, field, (cur) =>
        merge(cur === undefined ? empty : coerce(cur), snapshot),
      )
    } catch (err) {
      if (logTag) console.error(`${logTag} ${field}: failed to sync`, err)
    } finally {
      pending--
    }
  }

  function scheduleFlush(): void {
    if (flushTimer) return
    flushTimer = setTimeout(() => void flush(), flushDelayMs)
  }

  return {
    get: () => cache,
    subscribe(listener) {
      listeners.add(listener)
      return () => {
        listeners.delete(listener)
      }
    },
    loadFromKv,
    async hydrate(userId, serverPrefs) {
      activeKey = kvKey(userId)
      // Never clobber an in-flight optimistic write with a stale server read.
      if (pending > 0) return
      let base = cache
      if (foldKvOnHydrate) {
        const local = await loadFromKv(userId)
        base = merge(base, local) ?? base
      }
      const merged = merge(base, serverPrefs)
      const next = merged ?? base
      if (next === cache) return
      emit(next)
      const adapter = kv()
      if (adapter) await adapter.setItem(activeKey, JSON.stringify(next)).catch(() => {})
    },
    reset() {
      if (flushTimer) {
        clearTimeout(flushTimer)
        flushTimer = null
      }
      activeKey = null
      flushSession = null
      emit(empty)
    },
    async mutate(session, apply) {
      activeKey = kvKey(session.userId)
      const next = apply(cache)
      if (next !== null) {
        emit(next)
        persist()
      }
      if (flushDelayMs != null) {
        // Debounced: batch the server flush of the whole snapshot.
        flushSession = session
        scheduleFlush()
        return
      }
      // Write-through: apply the same per-operation change to the server's value.
      pending++
      try {
        await updateSpacesExtraField<T>(client(session), session, field, (cur) =>
          apply(cur === undefined ? empty : coerce(cur)),
        )
      } catch (err) {
        if (logTag) console.error(`${logTag} ${field}: failed to sync`, err)
      } finally {
        pending--
      }
    },
    flushNow: () => flush(),
  }
}
