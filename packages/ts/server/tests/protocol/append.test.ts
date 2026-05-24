import { describe, it, expect } from "vitest"
import { appendItem, type AppendConflict } from "../../src/protocol/push.js"
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

async function readDoc(store: ReturnType<typeof createIsolatedStore>, key: string) {
  const raw = await (store as any).getString(key)
  return raw ? JSON.parse(raw) : null
}

describe("appendItem", () => {
  it("empty store → single {ts, data} element; hash = hash({n:1, last})", async () => {
    const store = createIsolatedStore()
    const item = { msg: "hello" }
    const out = await appendItem(store, "col/doc", item, "items", undefined)
    expect("error" in out).toBe(false)
    const doc = await readDoc(store, "col/doc")
    expect(doc.data.items).toHaveLength(1)
    expect(doc.data.items[0].data).toEqual(item)
    expect(typeof doc.data.items[0].ts).toBe("number")
    expect((out as any).timestamp).toBe(doc.data.items[0].ts)
    expect((out as any).hash).toBe(await computeHash({ n: 1, last: item }))
    expect(doc.ts).toBe(doc.data.items[0].ts)
  })

  it("provided ts is stored verbatim (not now)", async () => {
    const store = createIsolatedStore()
    const out = await appendItem(store, "col/doc", { a: 1 }, "items", 5000)
    expect((out as any).timestamp).toBe(5000)
    const doc = await readDoc(store, "col/doc")
    expect(doc.data.items[0].ts).toBe(5000)
  })

  it("auto ts is strictly increasing across appends", async () => {
    const store = createIsolatedStore()
    await appendItem(store, "col/doc", { n: 1 }, "items", undefined)
    await appendItem(store, "col/doc", { n: 2 }, "items", undefined)
    const doc = await readDoc(store, "col/doc")
    expect(doc.data.items).toHaveLength(2)
    expect(doc.data.items[1].ts).toBeGreaterThan(doc.data.items[0].ts)
  })

  it("provided ts > latest is accepted", async () => {
    const store = createIsolatedStore()
    await appendItem(store, "col/doc", { n: 1 }, "items", 100)
    const out = await appendItem(store, "col/doc", { n: 2 }, "items", 200)
    expect((out as any).timestamp).toBe(200)
  })

  it("provided ts == latest → non_monotonic_timestamp conflict", async () => {
    const store = createIsolatedStore()
    await appendItem(store, "col/doc", { n: 1 }, "items", 100)
    const out = await appendItem(store, "col/doc", { n: 2 }, "items", 100)
    expect("error" in out).toBe(true)
    expect((out as AppendConflict).error).toBe("non_monotonic_timestamp")
    expect((out as AppendConflict).latest).toBe(100)
    // rejected append must not be stored
    const doc = await readDoc(store, "col/doc")
    expect(doc.data.items).toHaveLength(1)
  })

  it("provided ts < latest → non_monotonic_timestamp conflict", async () => {
    const store = createIsolatedStore()
    await appendItem(store, "col/doc", { n: 1 }, "items", 100)
    const out = await appendItem(store, "col/doc", { n: 2 }, "items", 50)
    expect((out as AppendConflict).error).toBe("non_monotonic_timestamp")
  })

  it("auto ts after a future provided ts stays strictly increasing", async () => {
    const store = createIsolatedStore()
    const future = Date.now() + 1_000_000
    await appendItem(store, "col/doc", { n: 1 }, "items", future)
    const out = await appendItem(store, "col/doc", { n: 2 }, "items", undefined)
    expect((out as any).timestamp).toBe(future + 1) // max(now, latest+1) === latest+1
  })

  it("hash reflects length and last item after multiple appends", async () => {
    const store = createIsolatedStore()
    await appendItem(store, "col/doc", { n: 1 }, "items", 1)
    const item2 = { n: 2 }
    const out = await appendItem(store, "col/doc", item2, "items", 2)
    expect((out as any).hash).toBe(await computeHash({ n: 2, last: item2 }))
  })

  it("custom appendField", async () => {
    const store = createIsolatedStore()
    await appendItem(store, "col/doc", { x: 1 }, "events", undefined)
    const doc = await readDoc(store, "col/doc")
    expect(doc.data.events).toHaveLength(1)
    expect(doc.data.events[0].data).toEqual({ x: 1 })
  })

  it("opaque data payload (e.g. ciphertext string) is stored as-is", async () => {
    const store = createIsolatedStore()
    // delegated-style payload: an encryptor wrapper object
    const wrapper = { _encrypted: "BASE64CIPHERTEXT", epoch: 1 }
    await appendItem(store, "col/doc", wrapper, "items", undefined)
    const doc = await readDoc(store, "col/doc")
    expect(doc.data.items[0].data).toEqual(wrapper)
  })

  it("concurrent appends to the same key both land (no lost write)", async () => {
    const store = createIsolatedStore()
    await Promise.all([
      appendItem(store, "col/doc", { n: 1 }, "items", undefined),
      appendItem(store, "col/doc", { n: 2 }, "items", undefined),
    ])
    const doc = await readDoc(store, "col/doc")
    expect(doc.data.items).toHaveLength(2)
    // serialised by the per-key write chain → strictly increasing ts preserved
    expect(doc.data.items[1].ts).toBeGreaterThan(doc.data.items[0].ts)
  })
})
