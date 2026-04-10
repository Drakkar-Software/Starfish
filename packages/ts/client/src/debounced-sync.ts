import type { StoreApi } from "zustand/vanilla"
import type { StarfishStore } from "./bindings/zustand.js"
import type { SyncManager } from "./sync.js"

// ── Shared types ──────────────────────────────────────────────────────────────

export interface DebouncedSyncOptions {
  /**
   * How long to wait after the last `notify()` call before pushing (default: 2000 ms).
   * Shorter values reduce latency; longer values batch more edits into a single push.
   */
  delayMs?: number
  /**
   * Emit a warning when the estimated encrypted payload exceeds this byte count (default: 900 KB).
   * The estimate multiplies the JSON size by 1.34 (base64 overhead for encrypted blobs).
   * Set to `Infinity` to disable.
   */
  warnBytes?: number
  /**
   * Block the push when the estimated encrypted payload exceeds this byte count (default: 1 MB).
   * Prevents cryptic 413 errors from the server. Set to `Infinity` to disable.
   */
  maxBytes?: number
  /**
   * Serialize store data to a sync document before pushing.
   * Called inside the debounce timer, so it always captures the latest state.
   * If omitted, `store.getState().data` is used as-is.
   */
  serialize?: (currentData: Record<string, unknown>) => Record<string, unknown>
  /**
   * Called when the estimated payload size exceeds `warnBytes` but is still below `maxBytes`.
   * Use to show a warning in the UI.
   */
  onSizeWarning?: (estimatedBytes: number) => void
  /**
   * Called when the estimated payload size exceeds `maxBytes`.
   * The push is blocked. Use to alert the user that data needs to be pruned.
   * If omitted, a console error is printed.
   */
  onSizeExceeded?: (estimatedBytes: number) => void
}

export interface DebouncedSync {
  /**
   * Schedule a push. If called again within `delayMs`, the timer resets.
   * Safe to call on every domain store mutation.
   */
  notify: () => void
  /** Cancel any pending debounced push. Does not affect an already-in-flight push. */
  cancel: () => void
}

export interface DebouncedPushOptions {
  /**
   * How long to wait after the last `notify()` call before pushing (default: 2000 ms).
   */
  delayMs?: number
  /**
   * Required: provides the document to push when the debounce timer fires.
   * Called inside the timer so it always captures the latest state.
   */
  serialize: () => Record<string, unknown>
  /**
   * Emit a warning when the estimated encrypted payload exceeds this byte count (default: 900 KB).
   * Set to `Infinity` to disable.
   */
  warnBytes?: number
  /**
   * Block the push when the estimated encrypted payload exceeds this byte count (default: 1 MB).
   * Set to `Infinity` to disable.
   */
  maxBytes?: number
  /**
   * Called when the estimated payload size exceeds `warnBytes` but is below `maxBytes`.
   */
  onSizeWarning?: (estimatedBytes: number) => void
  /**
   * Called when the estimated payload size exceeds `maxBytes`. The push is blocked.
   * If omitted, a console error is printed.
   */
  onSizeExceeded?: (estimatedBytes: number) => void
  /**
   * Called when `syncManager.push()` throws. Default: `console.warn`.
   */
  onError?: (err: unknown) => void
}

export interface DebouncedPush {
  /**
   * Schedule a push. If called again within `delayMs`, the timer resets.
   */
  notify: () => void
  /** Cancel any pending debounced push. Does not affect an already-in-flight push. */
  cancel: () => void
}

// ── Implementation ────────────────────────────────────────────────────────────

const DEFAULT_DELAY_MS = 2000
const DEFAULT_WARN_BYTES = 900 * 1024  // 900 KB
const DEFAULT_MAX_BYTES = 1024 * 1024  // 1 MB

interface SizeGuardOptions {
  warnBytes: number
  maxBytes: number
  onSizeWarning?: (bytes: number) => void
  onSizeExceeded?: (bytes: number) => void
}

/** Returns true if the push should be blocked. */
function checkPayloadSize(doc: Record<string, unknown>, opts: SizeGuardOptions): boolean {
  // Estimate encrypted payload size. AES-GCM output is similar to input size;
  // base64 encoding adds ~33% overhead, plus a small IV/tag overhead.
  const estimatedBytes = Math.ceil(JSON.stringify(doc).length * 1.34)

  if (estimatedBytes > opts.maxBytes) {
    if (opts.onSizeExceeded) {
      opts.onSizeExceeded(estimatedBytes)
    } else {
      console.error(
        `[starfish] Push blocked: estimated payload ${(estimatedBytes / 1024).toFixed(0)} KB ` +
        `exceeds limit of ${(opts.maxBytes / 1024).toFixed(0)} KB. Prune your data before syncing.`,
      )
    }
    return true
  }

  if (estimatedBytes > opts.warnBytes) {
    if (opts.onSizeWarning) {
      opts.onSizeWarning(estimatedBytes)
    } else {
      console.warn(
        `[starfish] Payload approaching limit: estimated ${(estimatedBytes / 1024).toFixed(0)} KB ` +
        `(warn threshold: ${(opts.warnBytes / 1024).toFixed(0)} KB).`,
      )
    }
  }

  return false
}

/**
 * Creates a debounced push helper that coalesces rapid mutations into a single sync.
 *
 * Designed to be called on every domain store mutation (e.g., every keystroke).
 * The push is delayed by `delayMs` after the **last** call, so typing quickly
 * results in one push, not one per character.
 *
 * Also estimates the encrypted payload size before pushing and warns / blocks
 * if it approaches the server's body size limit.
 *
 * ```ts
 * const { notify } = createDebouncedSync(starfishStore, {
 *   serialize: () => ({ tasks: taskStore.getState().tasks }),
 * })
 *
 * // Call on every domain store mutation:
 * taskStore.subscribe(() => notify())
 * ```
 */
export function createDebouncedSync(
  store: StoreApi<StarfishStore>,
  options: DebouncedSyncOptions = {},
): DebouncedSync {
  const {
    delayMs = DEFAULT_DELAY_MS,
    warnBytes = DEFAULT_WARN_BYTES,
    maxBytes = DEFAULT_MAX_BYTES,
    serialize,
    onSizeWarning,
    onSizeExceeded,
  } = options

  let timer: ReturnType<typeof setTimeout> | null = null

  function cancel(): void {
    if (timer !== null) {
      clearTimeout(timer)
      timer = null
    }
  }

  function notify(): void {
    cancel()
    timer = setTimeout(() => {
      timer = null
      const current = store.getState().data
      const doc = serialize ? serialize(current) : current

      if (checkPayloadSize(doc, { warnBytes, maxBytes, onSizeWarning, onSizeExceeded })) return

      store.getState().set(() => doc)
    }, delayMs)
  }

  return { notify, cancel }
}

/**
 * Creates a debounced push helper that calls `syncManager.push()` directly,
 * without requiring a Zustand store.
 *
 * Use this for one-way publishing workflows: public pages, derived snapshots,
 * or any case where you want to push data without a full `createStarfishStore` setup.
 *
 * ```ts
 * const syncManager = new SyncManager({ client, pullPath, pushPath })
 *
 * const { notify, cancel } = createDebouncedPush(syncManager, {
 *   serialize: () => buildPublicPageDocument(),
 * })
 *
 * // Push after every relevant store mutation:
 * planningStore.subscribe(() => notify())
 *
 * // Clean up on teardown:
 * cancel()
 * ```
 */
export function createDebouncedPush(
  syncManager: SyncManager,
  options: DebouncedPushOptions,
): DebouncedPush {
  const {
    delayMs = DEFAULT_DELAY_MS,
    warnBytes = DEFAULT_WARN_BYTES,
    maxBytes = DEFAULT_MAX_BYTES,
    serialize,
    onSizeWarning,
    onSizeExceeded,
    onError,
  } = options

  let timer: ReturnType<typeof setTimeout> | null = null

  function cancel(): void {
    if (timer !== null) {
      clearTimeout(timer)
      timer = null
    }
  }

  function notify(): void {
    cancel()
    timer = setTimeout(() => {
      timer = null
      const doc = serialize()

      if (checkPayloadSize(doc, { warnBytes, maxBytes, onSizeWarning, onSizeExceeded })) return

      syncManager.push(doc).catch((err: unknown) => {
        if (onError) {
          onError(err)
        } else {
          console.warn("[starfish] Push failed:", err)
        }
      })
    }, delayMs)
  }

  return { notify, cancel }
}
