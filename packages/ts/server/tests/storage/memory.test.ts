import { describe, it, expect } from "vitest"
import { MemoryObjectStore, CustomObjectStore } from "../../src/storage/memory.js"
import { createIsolatedStore } from "../helpers.js"

describe("MemoryObjectStore", () => {
  it("getString returns null for missing key", async () => {
    const store = createIsolatedStore()
    expect(await store.getString("missing")).toBeNull()
  })

  it("put and getString round-trip", async () => {
    const store = createIsolatedStore()
    await store.put("key1", "value1")
    expect(await store.getString("key1")).toBe("value1")
  })

  it("listKeys with prefix", async () => {
    const store = createIsolatedStore()
    await store.put("a/1", "v1")
    await store.put("a/2", "v2")
    await store.put("b/1", "v3")
    expect(await store.listKeys("a/")).toEqual(["a/1", "a/2"])
  })

  it("listKeys with startAfter and limit", async () => {
    const store = createIsolatedStore()
    await store.put("a/1", "v1")
    await store.put("a/2", "v2")
    await store.put("a/3", "v3")
    expect(await store.listKeys("a/", { startAfter: "a/1", limit: 1 })).toEqual(["a/2"])
  })

  it("delete removes key", async () => {
    const store = createIsolatedStore()
    await store.put("key1", "value1")
    await store.delete("key1")
    expect(await store.getString("key1")).toBeNull()
  })

  it("deleteMany removes multiple keys", async () => {
    const store = createIsolatedStore()
    await store.put("k1", "v1")
    await store.put("k2", "v2")
    await store.deleteMany(["k1", "k2"])
    expect(await store.getString("k1")).toBeNull()
    expect(await store.getString("k2")).toBeNull()
  })

  it("putBytes and getBytes round-trip", async () => {
    const store = createIsolatedStore()
    const data = new TextEncoder().encode("binary data")
    await store.putBytes("bin/1", data, { contentType: "image/png" })
    const result = await store.getBytes("bin/1")
    expect(result).not.toBeNull()
    expect(result!.contentType).toBe("image/png")
    expect(new TextDecoder().decode(result!.body)).toBe("binary data")
  })

  it("getBytes returns null for missing key", async () => {
    const store = createIsolatedStore()
    expect(await store.getBytes("missing")).toBeNull()
  })
})

describe("CustomObjectStore", () => {
  it("delegates to callbacks", async () => {
    const data = new Map<string, string>()
    const store = new CustomObjectStore({
      onGet: (key) => data.get(key) ?? null,
      onPut: (key, body) => { data.set(key, body) },
      onList: (prefix) => [...data.keys()].filter(k => k.startsWith(prefix)).sort(),
      onDelete: (key) => { data.delete(key) },
    })

    await store.put("a", "1")
    expect(await store.getString("a")).toBe("1")
    expect(await store.listKeys("")).toEqual(["a"])
    await store.delete("a")
    expect(await store.getString("a")).toBeNull()
  })

  it("returns defaults when no callbacks provided", async () => {
    const store = new CustomObjectStore({})
    expect(await store.getString("any")).toBeNull()
    expect(await store.listKeys("")).toEqual([])
  })
})
