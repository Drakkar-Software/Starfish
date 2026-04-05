import { describe, it, expect } from "vitest"
import { push } from "../../src/protocol/push.js"
import { isPushConflict, type StoredDocument } from "../../src/protocol/types.js"
import { createIsolatedStore } from "../helpers.js"

describe("push", () => {
  it("first push with null baseHash succeeds", async () => {
    const store = createIsolatedStore()
    const result = await push(store, "doc1", { name: "Alice" }, null)
    expect(isPushConflict(result)).toBe(false)
    if (!isPushConflict(result)) {
      expect(result.hash).toBeTruthy()
      expect(result.timestamp).toBeGreaterThan(0)
    }
  })

  it("first push with non-null baseHash fails", async () => {
    const store = createIsolatedStore()
    const result = await push(store, "doc1", { name: "Alice" }, "wronghash")
    expect(isPushConflict(result)).toBe(true)
  })

  it("second push with correct hash succeeds", async () => {
    const store = createIsolatedStore()
    const r1 = await push(store, "doc1", { name: "Alice" }, null)
    expect(isPushConflict(r1)).toBe(false)
    if (isPushConflict(r1)) return

    const r2 = await push(store, "doc1", { name: "Bob" }, r1.hash)
    expect(isPushConflict(r2)).toBe(false)
  })

  it("detects wrong hash", async () => {
    const store = createIsolatedStore()
    await push(store, "doc1", { name: "Alice" }, null)
    const r2 = await push(store, "doc1", { name: "Bob" }, "badhash")
    expect(isPushConflict(r2)).toBe(true)
  })

  it("stores document in correct format", async () => {
    const store = createIsolatedStore()
    await push(store, "doc1", { name: "Alice" }, null)
    const raw = await store.getString("doc1")
    expect(raw).toBeTruthy()
    const doc: StoredDocument = JSON.parse(raw!)
    expect(doc.v).toBe(1)
    expect(doc.data).toEqual({ name: "Alice" })
    expect(doc.hash).toBeTruthy()
    expect(doc.timestamps).toBeTruthy()
  })

  it("skips timestamps when requested", async () => {
    const store = createIsolatedStore()
    await push(store, "doc1", { name: "Alice" }, null, undefined, true)
    const raw = await store.getString("doc1")
    const doc: StoredDocument = JSON.parse(raw!)
    expect(doc.timestamps).toEqual({})
  })

  it("preserves timestamps for unchanged values", async () => {
    const store = createIsolatedStore()
    const r1 = await push(store, "doc1", { a: 1, b: 2 }, null)
    if (isPushConflict(r1)) return

    const raw1 = await store.getString("doc1")
    const doc1: StoredDocument = JSON.parse(raw1!)
    const tsA1 = doc1.timestamps.a

    // Wait a bit so timestamps differ
    await new Promise((r) => setTimeout(r, 5))

    await push(store, "doc1", { a: 1, b: 3 }, r1.hash)
    const raw2 = await store.getString("doc1")
    const doc2: StoredDocument = JSON.parse(raw2!)

    // a didn't change, its timestamp should be preserved
    expect(doc2.timestamps.a).toBe(tsA1)
    // b changed, its timestamp should be newer
    expect(doc2.timestamps.b).not.toBe(doc1.timestamps.b)
  })

  it("stores author info when provided", async () => {
    const store = createIsolatedStore()
    await push(store, "doc1", { x: 1 }, null, {
      pubkey: "pk123",
      signature: "sig456",
    })
    const raw = await store.getString("doc1")
    const doc: StoredDocument = JSON.parse(raw!)
    expect(doc.authorPubkey).toBe("pk123")
    expect(doc.authorSignature).toBe("sig456")
  })
})
