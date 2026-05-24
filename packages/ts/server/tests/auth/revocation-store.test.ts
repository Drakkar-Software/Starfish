import { describe, it, expect, beforeAll } from "vitest"
import { ed25519 } from "@noble/curves/ed25519.js"
import { sha256 } from "@noble/hashes/sha2.js"
import {
  configurePlatform,
  stableStringify,
} from "@drakkar.software/starfish-protocol"
import { webcrypto } from "node:crypto"
import {
  createInMemoryRevocationStore,
  revocationRetainUntilSec,
  REVOCATION_RETAIN_SKEW_SEC,
  type RevocationList,
  type RevocationEntry,
} from "../../src/auth/revocation-store.js"

beforeAll(() => {
  configurePlatform({
    crypto: webcrypto as any,
    base64: {
      encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
      decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
    },
  })
})

function bytesToHex(b: Uint8Array): string {
  let s = ""
  for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, "0")
  return s
}

function makeRootKeypair(seedByte: number): { priv: Uint8Array; pub: Uint8Array; pubHex: string; userId: string } {
  const priv = new Uint8Array(32).fill(seedByte)
  const pub = ed25519.getPublicKey(priv)
  const pubHex = bytesToHex(pub)
  const userId = bytesToHex(sha256(pub)).slice(0, 32)
  return { priv, pub, pubHex, userId }
}

function signList(
  list: Omit<RevocationList, "sig">,
  privKey: Uint8Array,
): RevocationList {
  const canonical = stableStringify(list as unknown as Record<string, unknown>)
  const sigBytes = ed25519.sign(new TextEncoder().encode(canonical), privKey)
  const sig = Buffer.from(sigBytes).toString("base64")
  return { ...list, sig }
}

describe("createInMemoryRevocationStore", () => {
  it("accepts a properly signed list and reports its entries as revoked", () => {
    const alice = makeRootKeypair(0x42)
    const store = createInMemoryRevocationStore()
    const entry: RevocationEntry = { sub: "sub-1", nonce: "nonce-1", exp: 9999999999 }
    const list = signList(
      {
        v: 1,
        iss: alice.pubHex,
        issUserId: alice.userId,
        generation: 1,
        revoked: [entry],
      },
      alice.priv,
    )
    const result = store.acceptList(list)
    expect(result.ok).toBe(true)
    expect(store.isRevoked(alice.pubHex, "sub-1", "nonce-1")).toBe(true)
    expect(store.isRevoked(alice.pubHex, "sub-1", "nonce-other")).toBe(false)
    expect(store.isRevoked(alice.pubHex, "sub-other", "nonce-1")).toBe(false)
  })

  it("accepts a generation-0 list as the first list for an issuer", () => {
    // The monotonicity gate rejects a generation <= the current one, but the very
    // first list has no current generation, so generation 0 is a valid starting
    // point (and a generation-0 replay is then rejected). Mirrors test_revocation_store.py.
    const alice = makeRootKeypair(0x43)
    const store = createInMemoryRevocationStore()
    const entry: RevocationEntry = { sub: "sub-z", nonce: "nonce-z", exp: 9999999999 }
    const gen0 = signList(
      { v: 1, iss: alice.pubHex, issUserId: alice.userId, generation: 0, revoked: [entry] },
      alice.priv,
    )
    expect(store.acceptList(gen0).ok).toBe(true)
    expect(store.isRevoked(alice.pubHex, "sub-z", "nonce-z")).toBe(true)
    // A second generation-0 list is now stale (not strictly greater).
    expect(store.acceptList(gen0).ok).toBe(false)
  })

  it("subject-level revoke invalidates every cap for that subject, including a fresh nonce", () => {
    const alice = makeRootKeypair(0x77)
    const store = createInMemoryRevocationStore()
    const list = signList(
      {
        v: 1,
        iss: alice.pubHex,
        issUserId: alice.userId,
        generation: 1,
        revoked: [],
        revokedSubjects: [{ sub: "device-sub", exp: 9999999999 }],
      },
      alice.priv,
    )
    expect(store.acceptList(list).ok).toBe(true)
    // A nonce never named individually is still revoked — this is what a
    // re-minted cap (fresh nonce) on a compromised device would carry.
    expect(store.isRevoked(alice.pubHex, "device-sub", "fresh-nonce")).toBe(true)
    expect(store.isRevoked(alice.pubHex, "device-sub", "another-nonce")).toBe(true)
    // A different subject is unaffected.
    expect(store.isRevoked(alice.pubHex, "other-sub", "fresh-nonce")).toBe(false)
  })

  it("a higher-generation list can lift a subject-level revoke", () => {
    const alice = makeRootKeypair(0x78)
    const store = createInMemoryRevocationStore()
    store.acceptList(
      signList(
        {
          v: 1, iss: alice.pubHex, issUserId: alice.userId, generation: 1,
          revoked: [], revokedSubjects: [{ sub: "device-sub", exp: 9999999999 }],
        },
        alice.priv,
      ),
    )
    expect(store.isRevoked(alice.pubHex, "device-sub", "n")).toBe(true)
    // Generation 2 omits the subject — the new list is authoritative.
    store.acceptList(
      signList(
        { v: 1, iss: alice.pubHex, issUserId: alice.userId, generation: 2, revoked: [] },
        alice.priv,
      ),
    )
    expect(store.isRevoked(alice.pubHex, "device-sub", "n")).toBe(false)
  })

  it("rejects a list with a forged signature", () => {
    const alice = makeRootKeypair(0x42)
    const bob = makeRootKeypair(0x99)
    const store = createInMemoryRevocationStore()
    const list = signList(
      {
        v: 1,
        iss: alice.pubHex,
        issUserId: alice.userId,
        generation: 1,
        revoked: [{ sub: "x", nonce: "y", exp: 100 }],
      },
      bob.priv, // wrong key
    )
    const result = store.acceptList(list)
    expect(result.ok).toBe(false)
    expect(store.isRevoked(alice.pubHex, "x", "y")).toBe(false)
  })

  it("rejects a list whose generation is not strictly greater than current", () => {
    const alice = makeRootKeypair(0x42)
    const store = createInMemoryRevocationStore()
    const list1 = signList(
      {
        v: 1,
        iss: alice.pubHex,
        issUserId: alice.userId,
        generation: 5,
        revoked: [{ sub: "sub-1", nonce: "n1", exp: 100 }],
      },
      alice.priv,
    )
    expect(store.acceptList(list1).ok).toBe(true)
    // Same generation
    const same = signList(
      {
        v: 1,
        iss: alice.pubHex,
        issUserId: alice.userId,
        generation: 5,
        revoked: [],
      },
      alice.priv,
    )
    const sameResult = store.acceptList(same)
    expect(sameResult.ok).toBe(false)
    // Lower generation
    const lower = signList(
      {
        v: 1,
        iss: alice.pubHex,
        issUserId: alice.userId,
        generation: 4,
        revoked: [],
      },
      alice.priv,
    )
    const lowerResult = store.acceptList(lower)
    expect(lowerResult.ok).toBe(false)
    // Original entry still revoked
    expect(store.isRevoked(alice.pubHex, "sub-1", "n1")).toBe(true)
  })

  it("replaces the list when a higher generation is accepted", () => {
    const alice = makeRootKeypair(0x42)
    const store = createInMemoryRevocationStore()
    const list1 = signList(
      {
        v: 1,
        iss: alice.pubHex,
        issUserId: alice.userId,
        generation: 1,
        revoked: [{ sub: "old-sub", nonce: "old-nonce", exp: 100 }],
      },
      alice.priv,
    )
    expect(store.acceptList(list1).ok).toBe(true)
    expect(store.isRevoked(alice.pubHex, "old-sub", "old-nonce")).toBe(true)

    const list2 = signList(
      {
        v: 1,
        iss: alice.pubHex,
        issUserId: alice.userId,
        generation: 2,
        revoked: [{ sub: "new-sub", nonce: "new-nonce", exp: 100 }],
      },
      alice.priv,
    )
    expect(store.acceptList(list2).ok).toBe(true)
    expect(store.isRevoked(alice.pubHex, "old-sub", "old-nonce")).toBe(false)
    expect(store.isRevoked(alice.pubHex, "new-sub", "new-nonce")).toBe(true)
  })

  it("returns false for unknown issuers", () => {
    const store = createInMemoryRevocationStore()
    expect(store.isRevoked("nope", "x", "y")).toBe(false)
  })

  // --- O(1) lookup + maxIssuers cap ---

  it("performs isRevoked in roughly constant time over large lists", () => {
    const alice = makeRootKeypair(0x42)
    const store = createInMemoryRevocationStore()
    const revoked: RevocationEntry[] = []
    for (let i = 0; i < 5000; i++) {
      revoked.push({ sub: `sub-${i}`, nonce: `nonce-${i}`, exp: 9_999_999_999 })
    }
    const list = signList(
      {
        v: 1,
        iss: alice.pubHex,
        issUserId: alice.userId,
        generation: 1,
        revoked,
      },
      alice.priv,
    )
    expect(store.acceptList(list).ok).toBe(true)
    // Make a worst-case lookup (last entry in the original list).
    const start = performance.now()
    for (let i = 0; i < 100; i++) {
      // hits — alternating to defeat any tiny one-shot caching
      store.isRevoked(alice.pubHex, "sub-4999", "nonce-4999")
      store.isRevoked(alice.pubHex, "sub-0", "nonce-0")
      // miss
      store.isRevoked(alice.pubHex, "sub-x", "nonce-x")
    }
    const elapsedMs = performance.now() - start
    // 300 lookups against a 5000-entry list. With O(1) this is well under a
    // millisecond even on cold V8; with the linear scan it's 100s of ms.
    expect(elapsedMs).toBeLessThan(50)
  })

  it("rebuilds the lookup index when a new generation replaces the list", () => {
    const alice = makeRootKeypair(0x42)
    const store = createInMemoryRevocationStore()
    const l1 = signList(
      {
        v: 1,
        iss: alice.pubHex,
        issUserId: alice.userId,
        generation: 1,
        revoked: [{ sub: "old", nonce: "n", exp: 100 }],
      },
      alice.priv,
    )
    expect(store.acceptList(l1).ok).toBe(true)
    expect(store.isRevoked(alice.pubHex, "old", "n")).toBe(true)

    const l2 = signList(
      {
        v: 1,
        iss: alice.pubHex,
        issUserId: alice.userId,
        generation: 2,
        revoked: [{ sub: "new", nonce: "n2", exp: 100 }],
      },
      alice.priv,
    )
    expect(store.acceptList(l2).ok).toBe(true)
    expect(store.isRevoked(alice.pubHex, "old", "n")).toBe(false)
    expect(store.isRevoked(alice.pubHex, "new", "n2")).toBe(true)
  })

  it("rejects new issuers beyond maxIssuers", () => {
    const a = makeRootKeypair(0x10)
    const b = makeRootKeypair(0x20)
    const c = makeRootKeypair(0x30)
    const store = createInMemoryRevocationStore({ maxIssuers: 2 })

    const mk = (k: { priv: Uint8Array; pubHex: string; userId: string }) =>
      signList(
        {
          v: 1,
          iss: k.pubHex,
          issUserId: k.userId,
          generation: 1,
          revoked: [],
        },
        k.priv,
      )

    expect(store.acceptList(mk(a)).ok).toBe(true)
    expect(store.acceptList(mk(b)).ok).toBe(true)
    const third = store.acceptList(mk(c))
    expect(third.ok).toBe(false)
    expect((third as { reason: string }).reason).toBe("too-many-issuers")
  })

  it("allows updates to an already-known issuer once at the maxIssuers cap", () => {
    const a = makeRootKeypair(0x10)
    const b = makeRootKeypair(0x20)
    const store = createInMemoryRevocationStore({ maxIssuers: 2 })

    const mk = (
      k: { priv: Uint8Array; pubHex: string; userId: string },
      gen: number,
    ) =>
      signList(
        {
          v: 1,
          iss: k.pubHex,
          issUserId: k.userId,
          generation: gen,
          revoked: [{ sub: `g-${gen}`, nonce: "n", exp: 1 }],
        },
        k.priv,
      )

    expect(store.acceptList(mk(a, 1)).ok).toBe(true)
    expect(store.acceptList(mk(b, 1)).ok).toBe(true)
    // Updating an existing issuer is fine even at the cap
    expect(store.acceptList(mk(a, 2)).ok).toBe(true)
    expect(store.isRevoked(a.pubHex, "g-2", "n")).toBe(true)
  })
})

describe("revocation entry retention (clock-skew slop)", () => {
  it("revocationRetainUntilSec returns exp + the resolver clock-skew slop", () => {
    const entry: RevocationEntry = { sub: "s", nonce: "n", exp: 1_000 }
    expect(REVOCATION_RETAIN_SKEW_SEC).toBe(300)
    expect(revocationRetainUntilSec(entry)).toBe(1_300)
    expect(revocationRetainUntilSec(entry, 0)).toBe(1_000)
  })

  it("keeps a cap revoked past its exp — the store never prunes by time", () => {
    // The resolver still accepts a cap until exp + skew, so an entry must
    // outlive exp. The in-memory store is generation-based and never time-
    // prunes, so isRevoked stays true regardless of how far past exp we are.
    const alice = makeRootKeypair(0x42)
    const store = createInMemoryRevocationStore()
    const exp = 1_000
    const entry: RevocationEntry = { sub: "leaked-sub", nonce: "leaked-nonce", exp }
    const list = signList(
      { v: 1, iss: alice.pubHex, issUserId: alice.userId, generation: 1, revoked: [entry] },
      alice.priv,
    )
    expect(store.acceptList(list).ok).toBe(true)
    // At exp, at exp+1, and well past the safe retain-until — still revoked.
    expect(store.isRevoked(alice.pubHex, "leaked-sub", "leaked-nonce")).toBe(true)
    expect(revocationRetainUntilSec(entry)).toBeGreaterThan(exp)
  })
})
