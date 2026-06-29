/**
 * Module-level per-document hash/data cache (octochat-style).
 *
 * Keyed by the verb-stripped path (`path.replace(/^\/(pull|push)\//, "")`), so a
 * doc's pull result and its push share one cache entry. Never stores an empty hash.
 *
 * Cleared on account switch via {@link clearDocCache} (called from clearNodeAccessCache).
 * In-memory only — hydrate re-pulls on boot, so persistence across restarts is unnecessary.
 */

interface DocCacheEntry {
  hash: string
  data?: Record<string, unknown>
}

const _cache = new Map<string, DocCacheEntry>()

/** Canonical doc identity: strip the /pull/ or /push/ verb so both map to one key. */
function docKey(path: string): string {
  return path.replace(/^\/(pull|push)\//, "")
}

/** Return the cached entry for the given path, or undefined. */
export function getCachedDoc(path: string): DocCacheEntry | undefined {
  return _cache.get(docKey(path))
}

/**
 * Record the hash from a pull or push-success.
 * No-op when `hash` is empty (a stale or missing-doc hash is not worth caching).
 */
export function noteHash(path: string, hash: string): void {
  if (!hash) return
  const k = docKey(path)
  const existing = _cache.get(k)
  _cache.set(k, { ...existing, hash })
}

/**
 * Record a full plaintext doc (index only). No-op when `hash` is empty.
 * Prefer this over `noteHash` for plaintext docs where the data is needed
 * to skip the pull on the next write (the mutator reads `cached.data`).
 */
export function noteDoc(path: string, hash: string, data: Record<string, unknown>): void {
  if (!hash) return
  _cache.set(docKey(path), { hash, data })
}

/** Evict a single entry (on definitive 404/410 or targeted invalidation). */
export function evictDoc(path: string): void {
  _cache.delete(docKey(path))
}

/** Clear the entire cache (on account switch — keys are per-identity). */
export function clearDocCache(): void {
  _cache.clear()
}
