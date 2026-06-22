/**
 * Tests for the space-access store.
 * Uses an in-memory KV adapter so no actual storage is needed.
 */
import { describe, it, expect, beforeEach } from "vitest"
import type { KvAdapter } from "../src/config.js"
import {
  hydrateSpaceAccessStore,
  getSpaceAccessEntry,
  saveSpaceAccessEntry,
  removeSpaceAccessEntry,
  getNodeAccessEntry,
  saveNodeAccessEntry,
  removeNodeAccessEntry,
  localSpaceAccessEntries,
  memberCapsFromStore,
  linkAccessFromStore,
  clearSpaceAccessStore,
  clearPersistedSpaceAccess,
} from "../src/space-access-store.js"

// In-memory KV adapter for testing
function makeKv(): KvAdapter & { store: Map<string, string> } {
  const store = new Map<string, string>()
  return {
    store,
    async getItem(key: string) {
      return store.get(key) ?? null
    },
    async setItem(key: string, value: string) {
      store.set(key, value)
    },
    async removeItem(key: string) {
      store.delete(key)
    },
  }
}

beforeEach(() => {
  clearSpaceAccessStore()
})

describe("hydrateSpaceAccessStore", () => {
  it("loads server member caps into memory", async () => {
    const kv = makeKv()
    await hydrateSpaceAccessStore("user1", { "sp-1": "cap-json" }, {}, kv)
    expect(getSpaceAccessEntry("sp-1")).toEqual({ kind: "member", cap: "cap-json" })
  })

  it("loads server link access into memory", async () => {
    const kv = makeKv()
    const linkAccess = { cap: {}, key: "ek", write: true }
    await hydrateSpaceAccessStore("user1", {}, { "sp-2": linkAccess }, kv)
    expect(getSpaceAccessEntry("sp-2")).toMatchObject({ kind: "link", key: "ek", write: true })
  })

  it("persists to KV on change", async () => {
    const kv = makeKv()
    await hydrateSpaceAccessStore("user1", { "sp-1": "cap" }, {}, kv)
    expect(kv.store.size).toBeGreaterThan(0)
  })

  it("loads from KV on first call for a user", async () => {
    const kv = makeKv()
    kv.store.set("octospaces.spaceaccess.user1", JSON.stringify({ "sp-3": { kind: "member", cap: "cached" } }))
    await hydrateSpaceAccessStore("user1", {}, {}, kv)
    expect(getSpaceAccessEntry("sp-3")).toEqual({ kind: "member", cap: "cached" })
  })

  it("server caps override KV cache", async () => {
    const kv = makeKv()
    kv.store.set("octospaces.spaceaccess.user1", JSON.stringify({ "sp-1": { kind: "member", cap: "old" } }))
    await hydrateSpaceAccessStore("user1", { "sp-1": "new-cap" }, {}, kv)
    expect(getSpaceAccessEntry("sp-1")).toEqual({ kind: "member", cap: "new-cap" })
  })
})

describe("saveSpaceAccessEntry / removeSpaceAccessEntry", () => {
  it("saves and retrieves an entry", async () => {
    await hydrateSpaceAccessStore("u", {}, {})
    saveSpaceAccessEntry("sp-x", { kind: "member", cap: "c" })
    expect(getSpaceAccessEntry("sp-x")).toEqual({ kind: "member", cap: "c" })
  })

  it("removes an entry", async () => {
    await hydrateSpaceAccessStore("u", {}, {})
    saveSpaceAccessEntry("sp-y", { kind: "member", cap: "c" })
    removeSpaceAccessEntry("sp-y")
    expect(getSpaceAccessEntry("sp-y")).toBeNull()
  })
})

describe("node-tier accessors", () => {
  it("saves and retrieves node content access", async () => {
    await hydrateSpaceAccessStore("u", {}, {})
    saveNodeAccessEntry("sp-1", "obj-1", { kind: "member", cap: "node-cap" })
    expect(getNodeAccessEntry("sp-1", "obj-1")).toEqual({ kind: "member", cap: "node-cap" })
  })

  it("removeNodeAccessEntry removes all three tiers", async () => {
    await hydrateSpaceAccessStore("u", {}, {})
    saveNodeAccessEntry("sp-1", "obj-1", { kind: "member", cap: "c" })
    removeNodeAccessEntry("sp-1", "obj-1")
    expect(getNodeAccessEntry("sp-1", "obj-1")).toBeNull()
  })
})

describe("memberCapsFromStore / linkAccessFromStore", () => {
  it("extracts member caps only", async () => {
    await hydrateSpaceAccessStore("u", { "sp-1": "cap1" }, {
      "sp-2": { cap: {}, key: "ek", write: false },
    })
    const caps = memberCapsFromStore()
    expect(caps).toEqual({ "sp-1": "cap1" })
    expect("sp-2" in caps).toBe(false)
  })

  it("extracts link access only", async () => {
    await hydrateSpaceAccessStore("u", { "sp-1": "cap1" }, {
      "sp-2": { cap: {}, key: "ek", write: true },
    })
    const links = linkAccessFromStore()
    expect("sp-1" in links).toBe(false)
    expect(links["sp-2"]).toMatchObject({ key: "ek", write: true })
  })
})

describe("clearPersistedSpaceAccess", () => {
  it("removes KV entry and clears in-memory state", async () => {
    const kv = makeKv()
    await hydrateSpaceAccessStore("user1", { "sp-1": "cap" }, {}, kv)
    clearPersistedSpaceAccess("user1", kv)
    expect(getSpaceAccessEntry("sp-1")).toBeNull()
    expect(kv.store.has("octospaces.spaceaccess.user1")).toBe(false)
  })
})
