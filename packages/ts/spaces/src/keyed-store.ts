/**
 * Lightweight in-memory keyed store with composable keys.
 *
 * Used internally by the spaces domain to track short-lived in-memory state
 * that should NOT be persisted (nonce maps, ephemeral invite stores, etc.).
 * For persistent cross-reload state see `space-access-store.ts`.
 */

/** A simple typed key-value bag with hydrate / serialize round-trip. */
export interface KeyedStore<T> {
  set(key: string, value: T): void
  get(key: string): T | undefined
  clear(key: string): void
  serialize(): string
  hydrate(raw: string): void
}

/** Create a fresh in-memory {@link KeyedStore}. */
export function createKeyedStore<T>(): KeyedStore<T> {
  const store = new Map<string, T>()
  return {
    set: (k, v) => {
      store.set(k, v)
    },
    get: (k) => store.get(k),
    clear: (k) => {
      store.delete(k)
    },
    serialize: () => JSON.stringify(Object.fromEntries(store)),
    hydrate: (raw) => {
      const obj: Record<string, T> = JSON.parse(raw)
      for (const [k, v] of Object.entries(obj)) store.set(k, v)
    },
  }
}

/**
 * Create a store backed by a single `KeyedStore<T>` where keys are computed by
 * composing multiple positional parts. The returned function accepts a fixed
 * argument list and returns a scoped `{ get; set; clear }` handle for that key.
 *
 * ```ts
 * const inviteStore = createComposedStore<StoredInvite, [spaceId: string]>(
 *   (spaceId) => `inv:${spaceId}`,
 * )
 * ```
 */
export function createComposedStore<T, K extends unknown[]>(
  composeKey: (...parts: K) => string,
): {
  store: KeyedStore<T>
  for(...parts: K): { get(): T | undefined; set(v: T): void; clear(): void }
} {
  const store = createKeyedStore<T>()
  return {
    store,
    for(...parts: K) {
      const key = composeKey(...parts)
      return {
        get: () => store.get(key),
        set: (v) => store.set(key, v),
        clear: () => store.clear(key),
      }
    },
  }
}
