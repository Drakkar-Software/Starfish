import { describe, it, expect } from "vitest"
import { pull } from "../../src/protocol/pull.js"
import { push } from "../../src/protocol/push.js"
import { isPushConflict } from "../../src/protocol/types.js"
import { createIsolatedStore } from "../helpers.js"

describe("pull", () => {
  it("returns empty data for non-existent document", async () => {
    const store = createIsolatedStore()
    const result = await pull(store, "missing")
    expect(result.data).toEqual({})
    expect(result.hash).toBe("")
    expect(result.timestamp).toBeGreaterThan(0)
  })

  it("returns full data after push", async () => {
    const store = createIsolatedStore()
    const pushResult = await push(store, "doc1", { name: "Alice", age: 30 }, null)
    expect(isPushConflict(pushResult)).toBe(false)

    const result = await pull(store, "doc1")
    expect(result.data).toEqual({ name: "Alice", age: 30 })
    expect(result.hash).toBeTruthy()
    expect(result.timestamp).toBeGreaterThan(0)
  })

  it("filters data with checkpoint", async () => {
    const store = createIsolatedStore()
    const r1 = await push(store, "doc1", { a: 1, b: 2 }, null)
    if (isPushConflict(r1)) return

    // Wait so timestamps differ
    await new Promise((r) => setTimeout(r, 5))

    const r2 = await push(store, "doc1", { a: 1, b: 3 }, r1.hash)
    if (isPushConflict(r2)) return

    // Pull with checkpoint from r1 — should only get changed keys
    const result = await pull(store, "doc1", r1.timestamp)
    // b changed, so it should appear. a didn't change.
    expect(result.data).toHaveProperty("b", 3)
    expect(result.data).not.toHaveProperty("a")
    // Hash should still be the full document hash
    expect(result.hash).toBe(r2.hash)
  })

  it("checkpoint 0 returns full data", async () => {
    const store = createIsolatedStore()
    await push(store, "doc1", { x: 1 }, null)
    const result = await pull(store, "doc1", 0)
    expect(result.data).toEqual({ x: 1 })
  })

  it("returns author info when present", async () => {
    const store = createIsolatedStore()
    await push(store, "doc1", { x: 1 }, null, {
      pubkey: "pk",
      signature: "sig",
    })
    const result = await pull(store, "doc1")
    expect(result.authorPubkey).toBe("pk")
    expect(result.authorSignature).toBe("sig")
  })
})
