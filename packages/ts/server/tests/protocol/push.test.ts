import { describe, it, expect } from "vitest"
import { push } from "../../src/protocol/push.js"
import { pull } from "../../src/protocol/pull.js"
import { createIsolatedStore } from "../helpers.js"
import { configurePlatform } from "@drakkarsoftware/starfish-protocol"
import { webcrypto } from "node:crypto"

// Configure platform for Node.js
configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

describe("push", () => {
  it("first push with null baseHash succeeds", async () => {
    const store = createIsolatedStore()
    const result = await push(store, "doc/1", { theme: "dark" }, null)
    expect("hash" in result && "timestamp" in result).toBe(true)
    expect((result as any).hash).toHaveLength(64)
  })

  it("first push with non-null baseHash returns conflict", async () => {
    const store = createIsolatedStore()
    const result = await push(store, "doc/1", { a: 1 }, "wrong-hash")
    expect("error" in result).toBe(true)
    expect((result as any).error).toBe("hash_mismatch")
  })

  it("second push with correct baseHash succeeds", async () => {
    const store = createIsolatedStore()
    const r1 = await push(store, "doc/1", { a: 1 }, null) as any
    const r2 = await push(store, "doc/1", { a: 2 }, r1.hash) as any
    expect(r2.hash).toHaveLength(64)
    expect(r2.hash).not.toBe(r1.hash)
  })

  it("second push with wrong baseHash returns conflict", async () => {
    const store = createIsolatedStore()
    await push(store, "doc/1", { a: 1 }, null)
    const r2 = await push(store, "doc/1", { a: 2 }, "wrong") as any
    expect(r2.error).toBe("hash_mismatch")
  })

  it("second push with null baseHash returns conflict", async () => {
    const store = createIsolatedStore()
    await push(store, "doc/1", { a: 1 }, null)
    const r2 = await push(store, "doc/1", { a: 2 }, null) as any
    expect(r2.error).toBe("hash_mismatch")
  })

  it("stores author info", async () => {
    const store = createIsolatedStore()
    await push(store, "doc/1", { a: 1 }, null, {
      pubkey: "pk1",
      signature: "sig1",
    })
    const raw = JSON.parse((await store.getString("doc/1"))!)
    expect(raw.authorPubkey).toBe("pk1")
    expect(raw.authorSignature).toBe("sig1")
  })

  it("push then pull returns same data", async () => {
    const store = createIsolatedStore()
    await push(store, "doc/1", { theme: "dark", lang: "en" }, null)
    const pulled = await pull(store, "doc/1")
    expect(pulled.data).toEqual({ theme: "dark", lang: "en" })
    expect(pulled.hash).toHaveLength(64)
  })

  it("skipTimestamps stores empty timestamps", async () => {
    const store = createIsolatedStore()
    await push(store, "doc/1", { a: 1 }, null, undefined, true)
    const raw = JSON.parse((await store.getString("doc/1"))!)
    expect(raw.timestamps).toEqual({})
  })
})
