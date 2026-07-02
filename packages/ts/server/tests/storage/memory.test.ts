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

  describe("compare-and-swap (getWithEtag / putIfMatch)", () => {
    it("getWithEtag returns null for a missing key", async () => {
      const store = createIsolatedStore()
      expect(await store.getWithEtag("missing")).toBeNull()
    })

    it("getWithEtag returns value and a stable etag; etag changes with content", async () => {
      const store = createIsolatedStore()
      await store.put("k", "v0")
      const g1 = await store.getWithEtag("k")
      expect(g1).not.toBeNull()
      expect(g1!.value).toBe("v0")
      const g2 = await store.getWithEtag("k")
      expect(g2!.etag).toBe(g1!.etag) // same content → same etag
      await store.put("k", "v1")
      const g3 = await store.getWithEtag("k")
      expect(g3!.etag).not.toBe(g1!.etag) // changed content → changed etag
    })

    it("putIfMatch(null) creates only when the key is absent", async () => {
      const store = createIsolatedStore()
      const created = await store.putIfMatch("k", "v0", null)
      expect(created).not.toBeNull()
      expect(await store.getString("k")).toBe("v0")
      // Second create-if-absent must fail — the key now exists.
      const again = await store.putIfMatch("k", "v1", null)
      expect(again).toBeNull()
      expect(await store.getString("k")).toBe("v0")
    })

    it("putIfMatch succeeds on a matching etag and fails on a stale one", async () => {
      const store = createIsolatedStore()
      await store.put("k", "v0")
      const g = await store.getWithEtag("k")
      const ok = await store.putIfMatch("k", "v1", g!.etag)
      expect(ok).not.toBeNull()
      // The old etag is now stale — a second write with it must fail.
      const stale = await store.putIfMatch("k", "v2", g!.etag)
      expect(stale).toBeNull()
      expect(await store.getString("k")).toBe("v1")
    })

    it("prevents a lost update across two instances sharing one bucket", async () => {
      const data = new Map<string, string>()
      const a = new MemoryObjectStore(data)
      const b = new MemoryObjectStore(data)
      await a.put("k", "v0")

      // Both instances read the same state before either writes.
      const gA = await a.getWithEtag("k")
      const gB = await b.getWithEtag("k")

      const rA = await a.putIfMatch("k", "vA", gA!.etag)
      expect(rA).not.toBeNull() // first writer wins

      const rB = await b.putIfMatch("k", "vB", gB!.etag)
      expect(rB).toBeNull() // second writer detects the conflict instead of clobbering

      // b re-reads and retries → its write now lands on top of vA.
      const gB2 = await b.getWithEtag("k")
      const rB2 = await b.putIfMatch("k", "vB", gB2!.etag)
      expect(rB2).not.toBeNull()
      expect(await a.getString("k")).toBe("vB")
    })
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
