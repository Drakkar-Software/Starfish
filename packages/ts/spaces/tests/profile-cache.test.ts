/**
 * Tests for the profile offline cache: cacheProfile / loadCachedProfile /
 * readProfileCached over the configured kvAdapter.
 */
import { describe, it, expect, beforeEach } from "vitest"
import { configureSpaces } from "../src/config.js"
import { cacheProfile, loadCachedProfile, readProfileCached } from "../src/client.js"
import type { SpaceLayout } from "../src/config.js"

function memKv() {
  const m = new Map<string, string>()
  return { m, adapter: { getItem: async (k: string) => m.get(k) ?? null, setItem: async (k: string, v: string) => void m.set(k, v), removeItem: async (k: string) => void m.delete(k) } }
}

const layout = { profilePull: (u: string) => `/pull/user/${u}/profile` } as unknown as SpaceLayout
const okFetch = (profile: unknown) => (async () => ({ ok: true, json: async () => ({ data: profile }) })) as unknown as typeof globalThis.fetch
const failFetch = (async () => ({ ok: false, json: async () => ({}) })) as unknown as typeof globalThis.fetch

beforeEach(() => configureSpaces({ kvAdapter: undefined }))

describe("profile offline cache", () => {
  it("cacheProfile + loadCachedProfile round-trip", async () => {
    const { adapter } = memKv()
    configureSpaces({ kvAdapter: adapter })
    const p = { pseudo: "alice", avatar: null, edPub: "e", kemPub: "k", kemSig: "s" }
    await cacheProfile("u1", p)
    expect(await loadCachedProfile("u1")).toEqual(p)
  })

  it("loadCachedProfile returns null with no kvAdapter or no cached value", async () => {
    expect(await loadCachedProfile("nope")).toBeNull()
    configureSpaces({ kvAdapter: memKv().adapter })
    expect(await loadCachedProfile("absent")).toBeNull()
  })

  it("readProfileCached caches a live hit, then falls back to it when offline", async () => {
    const { adapter } = memKv()
    configureSpaces({ kvAdapter: adapter })
    const p = { pseudo: "bob", avatar: null, edPub: "e", kemPub: "k", kemSig: "s" }
    const live = await readProfileCached("u2", { baseUrl: "http://x", layout, fetch: okFetch(p) })
    expect(live.pseudo).toBe("bob")
    const offline = await readProfileCached("u2", { baseUrl: "http://x", layout, fetch: failFetch })
    expect(offline.pseudo).toBe("bob") // served from cache, not the all-null live read
  })
})
