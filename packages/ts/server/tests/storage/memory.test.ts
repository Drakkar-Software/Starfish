import { describe, it, expect } from "vitest"
import { MemoryObjectStore, CustomObjectStore } from "../../src/storage/memory.js"
import { createIsolatedStore } from "../helpers.js"

describe("MemoryObjectStore", () => {
  it("returns null for missing key", async () => {
    const store = createIsolatedStore()
    expect(await store.getString("nope")).toBeNull()
  })

  it("put and get round-trip", async () => {
    const store = createIsolatedStore()
    await store.put("key1", '{"hello":"world"}')
    expect(await store.getString("key1")).toBe('{"hello":"world"}')
  })

  it("overwrites existing key", async () => {
    const store = createIsolatedStore()
    await store.put("k", "v1")
    await store.put("k", "v2")
    expect(await store.getString("k")).toBe("v2")
  })

  it("deletes key (idempotent)", async () => {
    const store = createIsolatedStore()
    await store.put("k", "v")
    await store.delete("k")
    expect(await store.getString("k")).toBeNull()
    // second delete is a no-op
    await store.delete("k")
  })

  it("deletes many keys", async () => {
    const store = createIsolatedStore()
    await store.put("a", "1")
    await store.put("b", "2")
    await store.put("c", "3")
    await store.deleteMany(["a", "c"])
    expect(await store.getString("a")).toBeNull()
    expect(await store.getString("b")).toBe("2")
    expect(await store.getString("c")).toBeNull()
  })

  it("lists keys with prefix", async () => {
    const store = createIsolatedStore()
    await store.put("users/alice", "1")
    await store.put("users/bob", "2")
    await store.put("posts/1", "3")
    const keys = await store.listKeys("users/")
    expect(keys).toEqual(["users/alice", "users/bob"])
  })

  it("lists keys with startAfter and limit", async () => {
    const store = createIsolatedStore()
    await store.put("a", "1")
    await store.put("b", "2")
    await store.put("c", "3")
    await store.put("d", "4")
    const keys = await store.listKeys("", { startAfter: "a", limit: 2 })
    expect(keys).toEqual(["b", "c"])
  })

  it("isolates stores with separate data", async () => {
    const store1 = createIsolatedStore()
    const store2 = createIsolatedStore()
    await store1.put("key", "val1")
    expect(await store2.getString("key")).toBeNull()
  })

  it("binary put/get round-trip", async () => {
    const store = createIsolatedStore()
    const data = Buffer.from("hello binary")
    await store.putBytes("bin", data, { contentType: "image/png" })
    const result = await store.getBytes("bin")
    expect(result).not.toBeNull()
    expect(result!.contentType).toBe("image/png")
    expect(result!.data.toString()).toBe("hello binary")
  })

  it("binary get returns null for missing key", async () => {
    const store = createIsolatedStore()
    expect(await store.getBytes("nope")).toBeNull()
  })

  it("delete clears binary data", async () => {
    const store = createIsolatedStore()
    await store.putBytes("bin", Buffer.from("data"), { contentType: "text/plain" })
    await store.delete("bin")
    expect(await store.getBytes("bin")).toBeNull()
  })
})

describe("CustomObjectStore", () => {
  it("delegates to callbacks", async () => {
    const data: Record<string, string> = {}
    const store = new CustomObjectStore({
      onGet: (key) => data[key] ?? null,
      onPut: (key, body) => { data[key] = body },
      onList: (prefix) => Object.keys(data).filter((k) => k.startsWith(prefix)).sort(),
      onDelete: (key) => { delete data[key] },
    })

    await store.put("key", "value")
    expect(await store.getString("key")).toBe("value")
    expect(await store.listKeys("")).toEqual(["key"])
    await store.delete("key")
    expect(await store.getString("key")).toBeNull()
  })

  it("supports async callbacks", async () => {
    const store = new CustomObjectStore({
      onGet: async (key) => (key === "x" ? "found" : null),
      onPut: async () => {},
      onList: async () => [],
      onDelete: async () => {},
    })
    expect(await store.getString("x")).toBe("found")
    expect(await store.getString("y")).toBeNull()
  })
})
