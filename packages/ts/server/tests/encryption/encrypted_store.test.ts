import { describe, it, expect } from "vitest"
import { EncryptedObjectStore } from "../../src/encryption/encrypted_store.js"
import { createIsolatedStore } from "../helpers.js"

describe("EncryptedObjectStore", () => {
  const SECRET = "test-secret-key"
  const SALT = "test-salt"

  it("round-trips encrypted data", async () => {
    const inner = createIsolatedStore()
    const store = new EncryptedObjectStore(inner, SECRET, SALT)
    await store.put("doc", '{"name":"Alice"}')
    const result = await store.getString("doc")
    expect(result).toBe('{"name":"Alice"}')
  })

  it("data is encrypted at rest", async () => {
    const inner = createIsolatedStore()
    const store = new EncryptedObjectStore(inner, SECRET, SALT)
    await store.put("doc", '{"name":"Alice"}')
    const raw = await inner.getString("doc")
    expect(raw).not.toBe('{"name":"Alice"}')
    expect(raw).toBeTruthy()
  })

  it("different salts produce different ciphertexts", async () => {
    const inner = createIsolatedStore()
    const store1 = new EncryptedObjectStore(inner, SECRET, "salt1")
    const store2 = new EncryptedObjectStore(inner, SECRET, "salt2")
    await store1.put("doc1", "hello")
    await store2.put("doc2", "hello")
    const raw1 = await inner.getString("doc1")
    const raw2 = await inner.getString("doc2")
    expect(raw1).not.toBe(raw2)
  })

  it("wrong key cannot decrypt", async () => {
    const inner = createIsolatedStore()
    const store1 = new EncryptedObjectStore(inner, SECRET, SALT)
    await store1.put("doc", "secret data")

    const store2 = new EncryptedObjectStore(inner, "wrong-key", SALT)
    await expect(store2.getString("doc")).rejects.toThrow()
  })

  it("returns null for missing key", async () => {
    const inner = createIsolatedStore()
    const store = new EncryptedObjectStore(inner, SECRET, SALT)
    expect(await store.getString("nope")).toBeNull()
  })

  it("delegates list and delete to inner store", async () => {
    const inner = createIsolatedStore()
    const store = new EncryptedObjectStore(inner, SECRET, SALT)
    await store.put("a", "1")
    await store.put("b", "2")
    const keys = await store.listKeys("")
    expect(keys).toEqual(["a", "b"])
    await store.delete("a")
    expect(await store.getString("a")).toBeNull()
  })

  it("deleteMany delegates to inner store", async () => {
    const inner = createIsolatedStore()
    const store = new EncryptedObjectStore(inner, SECRET, SALT)
    await store.put("x", "1")
    await store.put("y", "2")
    await store.deleteMany(["x", "y"])
    expect(await store.listKeys("")).toEqual([])
  })
})
