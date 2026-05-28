import { describe, it, expect } from "vitest"
import { push } from "../../src/protocol/push.js"
import { pull } from "../../src/protocol/pull.js"
import { createIsolatedStore } from "../helpers.js"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
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

  it("stores a single doc-level ts and no per-field timestamps tree", async () => {
    const store = createIsolatedStore()
    const before = Date.now()
    await push(store, "doc/1", { a: 1 }, null)
    const raw = JSON.parse((await store.getString("doc/1"))!)
    expect(typeof raw.ts).toBe("number")
    expect(raw.ts).toBeGreaterThanOrEqual(before)
    expect(raw.timestamps).toBeUndefined()
  })

  it("precomputedHash is used instead of computing hash", async () => {
    const store = createIsolatedStore()
    const sentinel = "a".repeat(64)
    await push(store, "doc/1", { a: 1 }, null, undefined, false, false, sentinel)
    const raw = JSON.parse((await store.getString("doc/1"))!)
    expect(raw.hash).toBe(sentinel)
  })

  it("a corrupt stored document does not crash push (returns a conflict, not a throw)", async () => {
    // Mirrors test_push.py — a non-JSON stored value must be handled gracefully.
    const store = createIsolatedStore()
    await store.put("doc/corrupt", "NOT_VALID_JSON")
    // Corrupt doc → currentHash = "" → baseHash=null with a present doc → conflict.
    const result = await push(store, "doc/corrupt", { a: 1 }, null) as any
    expect(result.error).toBe("hash_mismatch")
  })

  it("a corrupt stored document is overwritable with baseHash=''", async () => {
    // Mirrors test_push.py — baseHash="" matches the "" hash of a corrupt doc, so a
    // client that knows the doc is unreadable can recover it by overwriting.
    const store = createIsolatedStore()
    await store.put("doc/corrupt", "NOT_VALID_JSON")
    const result = await push(store, "doc/corrupt", { recovered: true }, "") as any
    expect(result.hash).toHaveLength(64)
  })
})
