import { describe, it, expect } from "vitest"
import { createInMemoryNonceCache } from "../../src/auth/nonce-cache.js"

describe("createInMemoryNonceCache", () => {
  it("accepts a fresh nonce and rejects the same nonce within the window", () => {
    const cache = createInMemoryNonceCache({ windowMs: 60_000 })
    const now = 1_000_000
    expect(cache.checkAndRemember("signer-a", "nonce-1", now)).toBe(true)
    expect(cache.checkAndRemember("signer-a", "nonce-1", now + 100)).toBe(false)
  })

  it("accepts the same nonce again once the window has elapsed", () => {
    const cache = createInMemoryNonceCache({ windowMs: 60_000 })
    const now = 1_000_000
    expect(cache.checkAndRemember("signer-a", "nonce-1", now)).toBe(true)
    expect(cache.checkAndRemember("signer-a", "nonce-1", now + 60_001)).toBe(true)
  })

  it("still rejects a replay at the exact expiry instant (no slot at 2× skew)", () => {
    const cache = createInMemoryNonceCache({ windowMs: 60_000 })
    const now = 1_000_000
    expect(cache.checkAndRemember("s", "n", now)).toBe(true)
    // At exactly now + windowMs the nonce must still be remembered. The window
    // is sized to 2× the clock skew; a clock-ahead request that first arrives
    // skew-early can be replayed exactly skew-late, landing on this instant.
    // Treating it as expired here would re-open that one-instant replay slot.
    expect(cache.checkAndRemember("s", "n", now + 60_000)).toBe(false)
    // One millisecond past the window it is finally forgotten.
    expect(cache.checkAndRemember("s", "n", now + 60_001)).toBe(true)
  })

  it("scopes nonces per signer — same nonce from a different signer is fresh", () => {
    const cache = createInMemoryNonceCache({ windowMs: 60_000 })
    const now = 1_000_000
    expect(cache.checkAndRemember("signer-a", "nonce-x", now)).toBe(true)
    expect(cache.checkAndRemember("signer-b", "nonce-x", now)).toBe(true)
  })

  it("uses defaults when no options are provided", () => {
    const cache = createInMemoryNonceCache()
    expect(cache.checkAndRemember("s", "n", Date.now())).toBe(true)
    expect(cache.checkAndRemember("s", "n", Date.now())).toBe(false)
  })

  // --- a LIVE nonce is never evicted (no replay under cap pressure) ---

  it("fails closed at maxEntries — rejects new nonces rather than evicting a live one", () => {
    const cache = createInMemoryNonceCache({ windowMs: 60_000, maxEntries: 3 })
    const now = 1_000_000
    expect(cache.checkAndRemember("s", "n1", now)).toBe(true)
    expect(cache.checkAndRemember("s", "n2", now)).toBe(true)
    expect(cache.checkAndRemember("s", "n3", now)).toBe(true)
    // Cache is full of LIVE entries → a fourth is rejected (not accepted by
    // evicting n1, which would make n1 replayable).
    expect(cache.checkAndRemember("s", "n4", now)).toBe(false)
    // n1 is still remembered → replay still rejected (the security property).
    expect(cache.checkAndRemember("s", "n1", now)).toBe(false)
  })

  it("reclaims expired entries to free capacity, then accepts again", () => {
    const cache = createInMemoryNonceCache({ windowMs: 60_000, maxEntries: 2 })
    const now = 1_000_000
    expect(cache.checkAndRemember("s", "n1", now)).toBe(true)
    expect(cache.checkAndRemember("s", "n2", now)).toBe(true)
    expect(cache.checkAndRemember("s", "n3", now)).toBe(false) // full of live entries
    // After the window elapses, n1/n2 expire and capacity frees up.
    expect(cache.checkAndRemember("s", "n3", now + 60_001)).toBe(true)
  })

  // --- per-signer cap ---

  it("fails closed at perSignerLimit — never evicts that signer's live nonce", () => {
    const cache = createInMemoryNonceCache({ windowMs: 60_000, perSignerLimit: 4 })
    const now = 1_000_000
    expect(cache.checkAndRemember("A", "a1", now)).toBe(true)
    expect(cache.checkAndRemember("A", "a2", now)).toBe(true)
    expect(cache.checkAndRemember("A", "a3", now)).toBe(true)
    expect(cache.checkAndRemember("A", "a4", now)).toBe(true)
    // A is at its cap with all-live entries → fifth nonce rejected.
    expect(cache.checkAndRemember("A", "a5", now)).toBe(false)
    // a1 was NOT evicted → replaying it is still rejected.
    expect(cache.checkAndRemember("A", "a1", now)).toBe(false)
  })

  it("does not let one signer's load affect another signer", () => {
    const cache = createInMemoryNonceCache({ windowMs: 60_000, perSignerLimit: 2 })
    const now = 1_000_000
    expect(cache.checkAndRemember("B", "b1", now)).toBe(true)
    expect(cache.checkAndRemember("B", "b2", now)).toBe(true)
    // Signer A saturates its own cap; A's overflow is rejected.
    expect(cache.checkAndRemember("A", "a1", now)).toBe(true)
    expect(cache.checkAndRemember("A", "a2", now)).toBe(true)
    expect(cache.checkAndRemember("A", "a3", now)).toBe(false)
    // B's nonces are untouched — still live, so replays are rejected (A's
    // saturation did not evict them).
    expect(cache.checkAndRemember("B", "b1", now)).toBe(false)
    expect(cache.checkAndRemember("B", "b2", now)).toBe(false)
    // Once one of B's entries expires, B can record a fresh nonce again.
    expect(cache.checkAndRemember("B", "b3", now + 60_001)).toBe(true)
  })

  it("default window spans at least 2× the 5-min clock skew (≥ 10 min)", () => {
    const cache = createInMemoryNonceCache()
    const now = 5_000_000
    expect(cache.checkAndRemember("s", "n", now)).toBe(true)
    // Still remembered just under 10 minutes later (would be replayable if the
    // window were the old 5 min).
    expect(cache.checkAndRemember("s", "n", now + 9 * 60_000)).toBe(false)
    // Past the 10-minute window it is finally forgotten.
    expect(cache.checkAndRemember("s", "n", now + 10 * 60_000 + 1)).toBe(true)
  })
})
