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

  it("regular pull always returns the full document (no checkpoint filtering)", async () => {
    const store = createIsolatedStore()
    await push(store, "doc/1", { a: 1, b: 2 }, null) as any
    const r1 = await pull(store, "doc/1")
    await push(store, "doc/1", { a: 1, b: 3, c: 4 }, r1.hash) as any

    // Incremental sync was removed for regular collections — the whole document
    // comes back regardless of how recently each field changed.
    const result = await pull(store, "doc/1")
    expect(result.data).toEqual({ a: 1, b: 3, c: 4 })
    expect(result.hash).toHaveLength(64)
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
