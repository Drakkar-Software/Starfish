/**
 * Server-side nonce cache for replay protection of v3 signed requests.
 *
 * Each authenticated request carries an Ed25519 signature over
 * (method, pathAndQuery, sha256(body), ts, nonce). The signer's public key
 * is bound to the cap-cert subject; the nonce alone does not give an
 * attacker replay capability so long as the server remembers it for the
 * acceptance window.
 *
 * This in-memory implementation is appropriate for single-process servers
 * or short-lived workers. Multi-instance deployments need a shared store —
 * use {@link createKvNonceCache} with a networked {@link KVAdapter}.
 */

import { type KVAdapter } from "../storage/kv-adapter.js"

/** Pluggable contract for a nonce-cache backend. */
export interface NonceCache {
  /**
   * Returns `true` iff `(signerEdPubHex, nonceBase64)` has not been seen
   * within the current acceptance window. A `true` result also marks the
   * nonce as seen (with expiry = `nowMs + windowMs`).
   *
   * Returns `false` for replays — same signer + same nonce within window.
   */
  checkAndRemember(signerEdPubHex: string, nonceBase64: string, nowMs: number): Promise<boolean>
}

/** Options for {@link createInMemoryNonceCache}. */
export interface NonceCacheOptions {
  /**
   * Acceptance window in milliseconds — how long a nonce is remembered.
   *
   * MUST be at least **2× the request clock-skew** the server accepts
   * (`DEFAULT_MAX_SKEW_MS` is 5 min, so the default here is 10 min). A request
   * is accepted anywhere in `[ts − skew, ts + skew]`; a clock-ahead request can
   * therefore first arrive up to `skew` *before* its `ts`, and a replay can be
   * attempted up to `skew` *after* it. Remembering the nonce for the full
   * `2 × skew` span guarantees a replay is still caught by the cache before the
   * skew gate would reject it. A shorter window re-opens a replay slot.
   */
  windowMs?: number
  /** Global cap on the total number of remembered nonces. Default 100 000. */
  maxEntries?: number
  /**
   * Per-signer cap on live nonces. Each signer's nonces sit in their own
   * sub-cache so a noisy signer can never displace another signer's entries.
   * Default 4 096.
   *
   * Caps are enforced **fail-closed**: when a cap is reached and every entry is
   * still within its window, a new nonce is *rejected* (returns `false`) rather
   * than evicting a live nonce — evicting a live nonce would let it be replayed.
   * Expired entries are always reclaimed first, so the caps only bite under a
   * genuine flood. Size them for your peak per-signer request rate over
   * `windowMs`, or use a shared store for multi-instance / high-throughput
   * deployments.
   */
  perSignerLimit?: number
}

// Default window is 2× DEFAULT_MAX_SKEW_MS (5 min) from the protocol's request
// signing — see the windowMs doc above for why this MUST be ≥ 2× skew.
const DEFAULT_WINDOW_MS = 10 * 60 * 1000
const DEFAULT_MAX_ENTRIES = 100_000
const DEFAULT_PER_SIGNER_LIMIT = 4_096

/**
 * Build an in-memory nonce cache. Entries expire `windowMs` after insertion.
 *
 * A **live** (non-expired) nonce is never evicted — doing so would re-open a
 * replay slot. Expired entries are reclaimed on each call; if a cap is reached
 * with all entries still live, the new nonce is rejected (fail closed).
 */
export function createInMemoryNonceCache(opts: NonceCacheOptions = {}): NonceCache {
  const windowMs = opts.windowMs ?? DEFAULT_WINDOW_MS
  const maxEntries = opts.maxEntries ?? DEFAULT_MAX_ENTRIES
  const perSignerLimit = opts.perSignerLimit ?? DEFAULT_PER_SIGNER_LIMIT
  // Map preserves insertion order, so iterating .keys() yields oldest first.
  // Because every entry uses the same `windowMs`, insertion order == expiry
  // order, so the oldest entries are always the first to expire.
  const seen = new Map<string, number>()
  // Per-signer index: signerEdPubHex → Map(nonceBase64 → exp).
  const bySigner = new Map<string, Map<string, number>>()

  function dropEntry(signer: string, nonce: string): void {
    seen.delete(`${signer}|${nonce}`)
    const sub = bySigner.get(signer)
    if (sub) {
      sub.delete(nonce)
      if (sub.size === 0) bySigner.delete(signer)
    }
  }

  return {
    async checkAndRemember(signerEdPubHex, nonceBase64, nowMs) {
      const key = `${signerEdPubHex}|${nonceBase64}`
      const existing = seen.get(key)
      if (existing !== undefined) {
        if (existing >= nowMs) {
          // Still within window (expiry == now still counts as live) → replay.
          return false
        }
        // Expired — drop so it can be re-inserted as fresh below.
        dropEntry(signerEdPubHex, nonceBase64)
      }

      // Reclaim ALL expired entries (oldest-first; stop at the first live one,
      // since insertion order == expiry order). This is what frees capacity —
      // never the eviction of a live nonce. An entry whose expiry equals `now`
      // is still live, matching the replay check above.
      for (const [k, exp] of seen) {
        if (exp >= nowMs) break
        const sepIdx = k.indexOf("|")
        if (sepIdx > 0) dropEntry(k.slice(0, sepIdx), k.slice(sepIdx + 1))
        else seen.delete(k)
      }

      // Fail closed when a cap is hit with all-live entries: reject rather than
      // evict a live nonce (which would let it be replayed).
      const subCache = bySigner.get(signerEdPubHex)
      if (subCache && subCache.size >= perSignerLimit) return false
      if (seen.size >= maxEntries) return false

      const expiry = nowMs + windowMs
      seen.set(key, expiry)
      let sub = bySigner.get(signerEdPubHex)
      if (!sub) {
        sub = new Map<string, number>()
        bySigner.set(signerEdPubHex, sub)
      }
      sub.set(nonceBase64, expiry)
      return true
    },
  }
}

/**
 * Build a nonce cache backed by a {@link KVAdapter} — e.g. a shared/networked store so
 * replay protection holds across multiple server instances. Each nonce is recorded under
 * `${signer}|${nonce}` with a `windowMs` TTL; the per-signer cap is passed as a
 * fail-closed group hint (honored by the in-memory adapter; networked adapters that can't
 * cheaply count a group may ignore it).
 *
 * **Best-effort on stores without atomic check-and-set** (e.g. Garage K2V): the record is
 * a read-then-write, so two *concurrent* requests carrying the *same* nonce can both be
 * accepted (a narrow TOCTOU window). This still closes the common replay case (a nonce
 * reused after the first request completes) and is strictly better than per-node caching
 * across multiple instances. Use a CAS-capable store (e.g. Redis) if you need to close the
 * concurrent-duplicate window completely.
 */
export function createKvNonceCache(kv: KVAdapter, opts: NonceCacheOptions = {}): NonceCache {
  const windowMs = opts.windowMs ?? DEFAULT_WINDOW_MS
  const perSignerLimit = opts.perSignerLimit ?? DEFAULT_PER_SIGNER_LIMIT
  return {
    async checkAndRemember(signerEdPubHex, nonceBase64, _nowMs) {
      // The backend's TTL drives expiry; `_nowMs` is unused (kept for interface parity).
      return kv.recordIfAbsent(`${signerEdPubHex}|${nonceBase64}`, windowMs, {
        key: signerEdPubHex,
        limit: perSignerLimit,
      })
    },
  }
}
