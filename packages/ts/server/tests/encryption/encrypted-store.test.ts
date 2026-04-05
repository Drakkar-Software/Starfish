import { describe, it, expect } from "vitest"
import { EncryptedObjectStore } from "../../src/encryption/encrypted-store.js"
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

describe("EncryptedObjectStore", () => {
  it("encrypts and decrypts round-trip", async () => {
    const inner = createIsolatedStore()
    const store = new EncryptedObjectStore(inner, "secret", "salt", "starfish-data")

    await store.put("key1", '{"hello":"world"}')
    const result = await store.getString("key1")
    expect(result).toBe('{"hello":"world"}')

    // Verify inner store has encrypted data (not plaintext)
    const raw = await inner.getString("key1")
    expect(raw).not.toBe('{"hello":"world"}')
    expect(raw).not.toBeNull()
  })

  it("returns null for missing key", async () => {
    const inner = createIsolatedStore()
    const store = new EncryptedObjectStore(inner, "secret", "salt")
    expect(await store.getString("missing")).toBeNull()
  })

  it("different salt produces different ciphertext", async () => {
    const inner1 = createIsolatedStore()
    const inner2 = createIsolatedStore()
    const store1 = new EncryptedObjectStore(inner1, "secret", "salt1")
    const store2 = new EncryptedObjectStore(inner2, "secret", "salt2")

    await store1.put("key", "value")
    await store2.put("key", "value")

    const raw1 = await inner1.getString("key")
    const raw2 = await inner2.getString("key")
    expect(raw1).not.toBe(raw2)
  })

  it("delegates listKeys to inner store", async () => {
    const inner = createIsolatedStore()
    const store = new EncryptedObjectStore(inner, "secret", "salt")

    await store.put("a/1", "val1")
    await store.put("a/2", "val2")
    await store.put("b/1", "val3")

    const keys = await store.listKeys("a/")
    expect(keys).toEqual(["a/1", "a/2"])
  })

  it("delegates delete to inner store", async () => {
    const inner = createIsolatedStore()
    const store = new EncryptedObjectStore(inner, "secret", "salt")

    await store.put("key1", "value")
    await store.delete("key1")
    expect(await store.getString("key1")).toBeNull()
    expect(await inner.getString("key1")).toBeNull()
  })
})
