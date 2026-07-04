/**
 * Tests for createSealedBlobStore — the cached sealed-blob store.
 *
 * Uses a fake client (pushBlob/pullBlob spies), a self-inverse XOR ByteSealer,
 * and an in-memory KV so the tests exercise the seal/transport/cache plumbing
 * without real AES-GCM or a network.
 */
import { describe, it, expect, vi } from "vitest"
import type { StarfishClient } from "../src/client.js"
import type { ByteSealer } from "../src/blob-seal.js"
import { createSealedBlobStore, FileTooLargeError } from "../src/sealed-blob-store.js"

interface Ctx {
  spaceId: string
}

function xorSealer(): ByteSealer {
  return {
    async sealBytes(bytes) {
      return bytes.map((b) => b ^ 0xaa)
    },
    async openBytes(blob) {
      return blob.map((b) => b ^ 0xaa)
    },
  }
}

function makeKv() {
  const map = new Map<string, string>()
  return {
    map,
    adapter: {
      getItem: async (k: string) => map.get(k) ?? null,
      setItem: async (k: string, v: string) => void map.set(k, v),
      removeItem: async (k: string) => void map.delete(k),
    },
  }
}

/** Fake client backed by an in-memory blob store; records pull calls. */
function makeClient() {
  const store = new Map<string, Uint8Array>()
  const pullSpy = vi.fn(async (path: string) => {
    const data = store.get(path.replace("/pull/", ""))
    if (!data) throw new Error("404")
    return { data: data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) }
  })
  const pushSpy = vi.fn(async (path: string, data: Uint8Array) => {
    store.set(path.replace("/push/", ""), new Uint8Array(data))
    return { hash: "h" }
  })
  const client = { pullBlob: pullSpy, pushBlob: pushSpy } as unknown as StarfishClient
  return { client, pullSpy, pushSpy, store }
}

const paths = {
  pushPath: (id: string, ctx: Ctx) => `/push/spaces/${ctx.spaceId}/blobs/${id}`,
  pullPath: (id: string, ctx: Ctx) => `/pull/spaces/${ctx.spaceId}/blobs/${id}`,
  aad: (id: string, ctx: Ctx) => `spaces/${ctx.spaceId}/blobs/${id}`,
}

describe("createSealedBlobStore", () => {
  it("upload seals bytes (ciphertext on the wire) and returns a blob id", async () => {
    const { client, store } = makeClient()
    let n = 0
    const blobs = createSealedBlobStore<Ctx>({ paths, maxBytes: 1000, genId: () => `id${++n}` })
    const bytes = new Uint8Array([1, 2, 3])
    const id = await blobs.upload(client, xorSealer(), bytes, { spaceId: "s1" })
    expect(id).toBe("id1")
    const stored = store.get("spaces/s1/blobs/id1")!
    expect(stored).toEqual(bytes.map((b) => b ^ 0xaa)) // sealed, not plaintext
  })

  it("enforces maxBytes with FileTooLargeError", async () => {
    const { client } = makeClient()
    const blobs = createSealedBlobStore<Ctx>({ paths, maxBytes: 2 })
    await expect(blobs.upload(client, null, new Uint8Array([1, 2, 3]), { spaceId: "s1" })).rejects.toBeInstanceOf(
      FileTooLargeError,
    )
  })

  it("load returns the uploaded plaintext and serves the memory cache on repeat", async () => {
    const { client, pullSpy } = makeClient()
    let n = 0
    const blobs = createSealedBlobStore<Ctx>({ paths, maxBytes: 1000, genId: () => `id${++n}` })
    const bytes = new Uint8Array([9, 8, 7])
    const id = await blobs.upload(client, xorSealer(), bytes, { spaceId: "s1" })
    const a = await blobs.load(client, xorSealer(), id, { spaceId: "s1" })
    expect(a).toEqual(bytes)
    expect(pullSpy).not.toHaveBeenCalled() // upload seeded the memory cache
  })

  it("after clearCache, reopens from persisted ciphertext without a network pull", async () => {
    const { client, pullSpy } = makeClient()
    const { adapter } = makeKv()
    let n = 0
    const blobs = createSealedBlobStore<Ctx>({ paths, maxBytes: 1000, kvAdapter: adapter, genId: () => `id${++n}` })
    const bytes = new Uint8Array([4, 5, 6])
    const id = await blobs.upload(client, xorSealer(), bytes, { spaceId: "s1" })
    blobs.clearCache()
    const a = await blobs.load(client, xorSealer(), id, { spaceId: "s1" })
    expect(a).toEqual(bytes)
    expect(pullSpy).not.toHaveBeenCalled() // served from the persisted ciphertext cache
  })

  it("falls back to a network pull when neither cache has the blob", async () => {
    const { client, pullSpy } = makeClient()
    // Upload with one store instance (no persistence), then load with a fresh instance.
    const uploader = createSealedBlobStore<Ctx>({ paths, maxBytes: 1000, genId: () => "fixed" })
    const bytes = new Uint8Array([2, 4, 6])
    const id = await uploader.upload(client, xorSealer(), bytes, { spaceId: "s1" })
    const reader = createSealedBlobStore<Ctx>({ paths, maxBytes: 1000 })
    const a = await reader.load(client, xorSealer(), id, { spaceId: "s1" })
    expect(a).toEqual(bytes)
    expect(pullSpy).toHaveBeenCalledTimes(1)
  })

  it("plaintext mode (sealer null) stores raw bytes", async () => {
    const { client, store } = makeClient()
    const blobs = createSealedBlobStore<Ctx>({ paths, maxBytes: 1000, genId: () => "p1" })
    const bytes = new Uint8Array([7, 7, 7])
    await blobs.upload(client, null, bytes, { spaceId: "s1" })
    expect(store.get("spaces/s1/blobs/p1")).toEqual(bytes)
  })
})
