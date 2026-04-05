import { describe, it, expect } from "vitest"
import { pull } from "../../src/protocol/pull.js"
import { push } from "../../src/protocol/push.js"
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

describe("pull", () => {
  it("pull from empty store returns empty data", async () => {
    const store = createIsolatedStore()
    const result = await pull(store, "doc/1")
    expect(result.data).toEqual({})
    expect(result.hash).toBe("")
    expect(typeof result.timestamp).toBe("number")
  })

  it("pull after push returns pushed data", async () => {
    const store = createIsolatedStore()
    const pushResult = await push(store, "doc/1", { a: 1, b: 2 }, null) as any
    const pullResult = await pull(store, "doc/1")
    expect(pullResult.data).toEqual({ a: 1, b: 2 })
    expect(pullResult.hash).toBe(pushResult.hash)
  })

  it("pull with checkpoint filters to newer keys", async () => {
    const store = createIsolatedStore()
    await push(store, "doc/1", { a: 1, b: 2 }, null) as any
    const checkpoint = Date.now()

    // Small delay to ensure timestamp difference
    await new Promise((r) => setTimeout(r, 5))

    const r1 = await pull(store, "doc/1")
    await push(store, "doc/1", { a: 1, b: 3, c: 4 }, r1.hash) as any

    const filtered = await pull(store, "doc/1", checkpoint)
    // b changed, c is new — a is unchanged (should be filtered)
    expect(filtered.data).toHaveProperty("b", 3)
    expect(filtered.data).toHaveProperty("c", 4)
    expect(filtered.data).not.toHaveProperty("a")
    // Hash is always the full document hash
    expect(filtered.hash).toHaveLength(64)
  })

  it("pull with checkpoint=0 returns full data", async () => {
    const store = createIsolatedStore()
    await push(store, "doc/1", { x: 1 }, null)
    const result = await pull(store, "doc/1", 0)
    expect(result.data).toEqual({ x: 1 })
  })

  it("preserves author fields", async () => {
    const store = createIsolatedStore()
    await push(store, "doc/1", { a: 1 }, null, {
      pubkey: "pk",
      signature: "sig",
    })
    const result = await pull(store, "doc/1")
    expect(result.authorPubkey).toBe("pk")
    expect(result.authorSignature).toBe("sig")
  })
})
