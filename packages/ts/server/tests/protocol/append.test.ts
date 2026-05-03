import { describe, it, expect } from "vitest"
import { buildAppendOnlyData, checkLastItemConflict } from "../../src/protocol/append.js"
import { push } from "../../src/protocol/push.js"
import { computeHash } from "@drakkar.software/starfish-protocol"
import { createIsolatedStore } from "../helpers.js"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { webcrypto } from "node:crypto"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

const NOW = 1714000000

describe("buildAppendOnlyData", () => {
  it("empty store → single-item array with empty baseHash", async () => {
    const store = createIsolatedStore()
    const { data, baseHash } = await buildAppendOnlyData(store, "col/doc", { msg: "hello" }, "items", NOW)
    expect(data).toEqual({ items: [{ msg: "hello" }] })
    expect(baseHash).toBe("")
  })

  it("existing doc with array → appends to end", async () => {
    const store = createIsolatedStore()
    await push(store, "col/doc", { items: [{ msg: "first" }] }, null)
    const { data } = await buildAppendOnlyData(store, "col/doc", { msg: "second" }, "items", NOW)
    expect(data).toEqual({ items: [{ msg: "first" }, { msg: "second" }] })
  })

  it("returns current hash from existing doc as baseHash", async () => {
    const store = createIsolatedStore()
    const r = await push(store, "col/doc", { items: [] }, null) as any
    const { baseHash } = await buildAppendOnlyData(store, "col/doc", { msg: "x" }, "items", NOW)
    expect(baseHash).toBe(r.hash)
  })

  it("existing doc with non-array items → recovers with single-item array", async () => {
    const store = createIsolatedStore()
    await push(store, "col/doc", { items: "not-an-array" }, null)
    const { data } = await buildAppendOnlyData(store, "col/doc", { msg: "x" }, "items", NOW)
    expect(data).toEqual({ items: [{ msg: "x" }] })
  })

  it("corrupt JSON in store → recovers as empty doc", async () => {
    const store = createIsolatedStore()
    await (store as any).put("col/doc", "NOT_JSON", { contentType: "application/json" })
    const { data, baseHash } = await buildAppendOnlyData(store, "col/doc", { a: 1 }, "items", NOW)
    expect(data).toEqual({ items: [{ a: 1 }] })
    expect(baseHash).toBe("")
  })

  it("custom appendField", async () => {
    const store = createIsolatedStore()
    const { data } = await buildAppendOnlyData(store, "col/doc", { x: 1 }, "events", NOW)
    expect(data).toEqual({ events: [{ x: 1 }] })
  })

  it("preserves other top-level data fields", async () => {
    const store = createIsolatedStore()
    await push(store, "col/doc", { items: [{ a: 1 }], meta: "info" }, null)
    const { data } = await buildAppendOnlyData(store, "col/doc", { a: 2 }, "items", NOW)
    expect((data as any).meta).toBe("info")
    expect((data as any).items).toEqual([{ a: 1 }, { a: 2 }])
  })

  it("returns parallel timestamps array with one entry per item", async () => {
    const store = createIsolatedStore()
    const { timestamps } = await buildAppendOnlyData(store, "col/doc", { msg: "first" }, "items", NOW)
    expect((timestamps as any)["items"]).toEqual([NOW])
  })

  it("appends NOW to existing timestamps array", async () => {
    const store = createIsolatedStore()
    // First append via buildAppendOnlyData to establish per-item shape
    const r1 = await buildAppendOnlyData(store, "col/doc", { n: 1 }, "items", NOW)
    await push(store, "col/doc", r1.data, r1.baseHash, undefined, false, false, r1.lastItemHash, r1.timestamps)
    const r2 = await buildAppendOnlyData(store, "col/doc", { n: 2 }, "items", NOW + 1)
    expect((r2.timestamps as any)["items"]).toEqual([NOW, NOW + 1])
  })

  it("returns length-tagged lastItemHash: hash({ n, last })", async () => {
    const store = createIsolatedStore()
    const item = { msg: "hello" }
    const { lastItemHash } = await buildAppendOnlyData(store, "col/doc", item, "items", NOW)
    const expected = await computeHash({ n: 1, last: item })
    expect(lastItemHash).toBe(expected)
  })

  it("lastItemHash reflects correct length after multiple appends", async () => {
    const store = createIsolatedStore()
    const item1 = { n: 1 }
    const item2 = { n: 2 }
    const r1 = await buildAppendOnlyData(store, "col/doc", item1, "items", NOW)
    await push(store, "col/doc", r1.data, r1.baseHash, undefined, false, false, r1.lastItemHash, r1.timestamps)
    const r2 = await buildAppendOnlyData(store, "col/doc", item2, "items", NOW + 1)
    const expected = await computeHash({ n: 2, last: item2 })
    expect(r2.lastItemHash).toBe(expected)
  })
})

// Helper: write a doc as the appendOnly push path would (length-tagged stored hash)
async function storeAsAppendOnly(
  store: ReturnType<typeof createIsolatedStore>,
  key: string,
  items: Record<string, unknown>[],
  field = "items",
) {
  if (items.length === 0) {
    // Use push with a placeholder hash
    await push(store, key, { [field]: [] }, null)
    return
  }
  const r = await buildAppendOnlyData(store, key, items[0], field, NOW)
  await push(store, key, r.data, r.baseHash, undefined, false, false, r.lastItemHash, r.timestamps)
  for (let i = 1; i < items.length; i++) {
    const ri = await buildAppendOnlyData(store, key, items[i], field, NOW + i)
    await push(store, key, ri.data, ri.baseHash, undefined, false, false, ri.lastItemHash, ri.timestamps)
  }
}

describe("checkLastItemConflict", () => {
  it("empty store + empty clientBaseHash → no conflict", async () => {
    const store = createIsolatedStore()
    const result = await checkLastItemConflict(store, "col/doc", "", "items")
    expect(result).toBeNull()
  })

  it("empty store + non-empty clientBaseHash → hash_mismatch", async () => {
    const store = createIsolatedStore()
    const result = await checkLastItemConflict(store, "col/doc", "somehash", "items")
    expect(result).toBe("hash_mismatch")
  })

  it("stored doc + matching stored hash → no conflict", async () => {
    const store = createIsolatedStore()
    const item = { msg: "hello" }
    await storeAsAppendOnly(store, "col/doc", [item])
    const storedHash = await computeHash({ n: 1, last: item })
    const result = await checkLastItemConflict(store, "col/doc", storedHash, "items")
    expect(result).toBeNull()
  })

  it("stored doc + stale hash → hash_mismatch", async () => {
    const store = createIsolatedStore()
    await storeAsAppendOnly(store, "col/doc", [{ msg: "hello" }])
    const result = await checkLastItemConflict(store, "col/doc", "stalehash", "items")
    expect(result).toBe("hash_mismatch")
  })

  it("stored doc + null clientBaseHash → hash_mismatch (doc exists)", async () => {
    const store = createIsolatedStore()
    await storeAsAppendOnly(store, "col/doc", [{ msg: "hello" }])
    const result = await checkLastItemConflict(store, "col/doc", null, "items")
    expect(result).toBe("hash_mismatch")
  })

  it("corrupt JSON → hash_mismatch", async () => {
    const store = createIsolatedStore()
    await (store as any).put("col/doc", "NOT_JSON", { contentType: "application/json" })
    const result = await checkLastItemConflict(store, "col/doc", "", "items")
    expect(result).toBe("hash_mismatch")
  })
})
