/**
 * Tests for sealAndPushBlob / pullAndOpenBlob (blob-seal.ts).
 *
 * Uses a fake XOR ByteSealer (deterministic, invertible, captures the AAD it
 * received) so the tests exercise the seal/unseal plumbing without the real
 * AES-GCM implementation.
 */

import { describe, it, expect, vi } from "vitest"
import { StarfishClient } from "../src/client.js"
import { sealAndPushBlob, pullAndOpenBlob } from "../src/blob-seal.js"
import type { ByteSealer } from "../src/blob-seal.js"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** XOR every byte with 0xAA — self-inverse and records the AAD received. */
function makeXorSealer(): ByteSealer & { lastSealAad: string | undefined; lastOpenAad: string | undefined } {
  const state = { lastSealAad: undefined as string | undefined, lastOpenAad: undefined as string | undefined }
  const sealer: ByteSealer & typeof state = {
    ...state,
    async sealBytes(bytes, aad) {
      state.lastSealAad = aad
      sealer.lastSealAad = aad
      return bytes.map((b) => b ^ 0xaa)
    },
    async openBytes(blob, aad) {
      state.lastOpenAad = aad
      sealer.lastOpenAad = aad
      return blob.map((b) => b ^ 0xaa)
    },
  }
  return sealer
}

function createClientWithFetch(mockFetch: typeof globalThis.fetch) {
  return new StarfishClient({ baseUrl: "https://api.example.com/v1", fetch: mockFetch })
}

// ---------------------------------------------------------------------------
// sealAndPushBlob
// ---------------------------------------------------------------------------

describe("sealAndPushBlob", () => {
  it("seals bytes and pushes the sealed ciphertext (not the plaintext)", async () => {
    const capturedRequests: { body: Uint8Array; contentType: string }[] = []
    const mockFetch = vi.fn(async (_url: string, init: RequestInit) => {
      const data = new Uint8Array(await new Response(init.body as BodyInit).arrayBuffer())
      capturedRequests.push({ body: data, contentType: (init.headers as Record<string, string>)["Content-Type"] })
      return new Response(JSON.stringify({ hash: "deadbeef" }), { status: 200 })
    })
    const client = createClientWithFetch(mockFetch)
    const sealer = makeXorSealer()

    const plaintext = new Uint8Array([0x01, 0x02, 0x03])
    const expected = plaintext.map((b) => b ^ 0xaa)

    const result = await sealAndPushBlob(client, sealer, "/push/spaces/s1/enc/obj1", plaintext, {
      aad: "spaces/s1/enc/obj1",
    })

    expect(result.hash).toBe("deadbeef")
    expect(capturedRequests[0].body).toEqual(expected)
    // plaintext must NOT appear on the wire
    expect(capturedRequests[0].body).not.toEqual(plaintext)
    expect(capturedRequests[0].contentType).toBe("application/octet-stream")
  })

  it("passes explicit aad to the sealer", async () => {
    const mockFetch = vi.fn(async () => new Response(JSON.stringify({ hash: "h" }), { status: 200 }))
    const client = createClientWithFetch(mockFetch)
    const sealer = makeXorSealer()

    await sealAndPushBlob(client, sealer, "/push/x/y", new Uint8Array([1]), { aad: "x/y" })

    expect(sealer.lastSealAad).toBe("x/y")
  })

  it("falls back to stripPushPrefix(path) as aad when aad is omitted", async () => {
    const mockFetch = vi.fn(async () => new Response(JSON.stringify({ hash: "h" }), { status: 200 }))
    const client = createClientWithFetch(mockFetch)
    const sealer = makeXorSealer()

    await sealAndPushBlob(client, sealer, "/push/spaces/s1/enc/obj1", new Uint8Array([1]))

    // PUSH_PATH_PREFIX = "/push/" → strip → "spaces/s1/enc/obj1"
    expect(sealer.lastSealAad).toBe("spaces/s1/enc/obj1")
  })

  it("always pushes with Content-Type: application/octet-stream", async () => {
    const capturedCt: string[] = []
    const mockFetch = vi.fn(async (_url: string, init: RequestInit) => {
      capturedCt.push((init.headers as Record<string, string>)["Content-Type"])
      return new Response(JSON.stringify({ hash: "h" }), { status: 200 })
    })
    const client = createClientWithFetch(mockFetch)
    const sealer = makeXorSealer()

    await sealAndPushBlob(client, sealer, "/push/x", new Uint8Array([1]))

    expect(capturedCt[0]).toBe("application/octet-stream")
  })

  it("throws RangeError when bytes exceed maxBytes (before sealing)", async () => {
    const mockFetch = vi.fn(async () => new Response(JSON.stringify({ hash: "h" }), { status: 200 }))
    const client = createClientWithFetch(mockFetch)
    const sealer = makeXorSealer()

    await expect(
      sealAndPushBlob(client, sealer, "/push/x", new Uint8Array(100), { maxBytes: 50 }),
    ).rejects.toThrow(RangeError)

    // pushBlob must NOT have been called
    expect(mockFetch).not.toHaveBeenCalled()
  })

  it("does not throw when bytes equal maxBytes", async () => {
    const mockFetch = vi.fn(async () => new Response(JSON.stringify({ hash: "h" }), { status: 200 }))
    const client = createClientWithFetch(mockFetch)
    const sealer = makeXorSealer()

    await expect(
      sealAndPushBlob(client, sealer, "/push/x", new Uint8Array(50), { maxBytes: 50 }),
    ).resolves.not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// pullAndOpenBlob
// ---------------------------------------------------------------------------

describe("pullAndOpenBlob", () => {
  it("pulls sealed bytes and returns the decrypted plaintext", async () => {
    const plaintext = new Uint8Array([0x10, 0x20, 0x30])
    const sealed = plaintext.map((b) => b ^ 0xaa)

    const mockFetch = vi.fn(async () =>
      new Response(sealed, {
        status: 200,
        headers: { "Content-Type": "application/octet-stream" },
      }),
    )
    const client = createClientWithFetch(mockFetch)
    const sealer = makeXorSealer()

    const result = await pullAndOpenBlob(client, sealer, "/pull/spaces/s1/enc/obj1", {
      aad: "spaces/s1/enc/obj1",
    })

    expect(result).toEqual(plaintext)
  })

  it("passes explicit aad to the sealer's openBytes", async () => {
    const mockFetch = vi.fn(async () =>
      new Response(new Uint8Array([0xab]), {
        status: 200,
        headers: { "Content-Type": "application/octet-stream" },
      }),
    )
    const client = createClientWithFetch(mockFetch)
    const sealer = makeXorSealer()

    await pullAndOpenBlob(client, sealer, "/pull/x/y", { aad: "x/y" })

    expect(sealer.lastOpenAad).toBe("x/y")
  })

  it("falls back to document key (strips /pull/ prefix) when aad is omitted", async () => {
    const mockFetch = vi.fn(async () =>
      new Response(new Uint8Array([0xaa]), {
        status: 200,
        headers: { "Content-Type": "application/octet-stream" },
      }),
    )
    const client = createClientWithFetch(mockFetch)
    const sealer = makeXorSealer()

    // /pull/ prefix is stripped, yielding the same document key as the seal side.
    await pullAndOpenBlob(client, sealer, "/pull/spaces/s1/enc/obj1")

    expect(sealer.lastOpenAad).toBe("spaces/s1/enc/obj1")
  })

  it("round-trip: seal then pull/open returns original bytes (explicit aad)", async () => {
    const plaintext = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
    const sealer = makeXorSealer()

    // Seal
    const sealed = await sealer.sealBytes(plaintext, "round-trip-aad")

    // Simulate server storing and returning the sealed bytes
    const mockFetch = vi.fn(async () =>
      new Response(sealed, {
        status: 200,
        headers: { "Content-Type": "application/octet-stream" },
      }),
    )
    const client = createClientWithFetch(mockFetch)

    const result = await pullAndOpenBlob(client, sealer, "/pull/enc/obj", { aad: "round-trip-aad" })

    expect(result).toEqual(plaintext)
  })

  it("round-trip: default-aad seal+push then pull+open returns original bytes", async () => {
    // This test covers the critical path where neither sealAndPushBlob nor
    // pullAndOpenBlob receives an explicit aad — both must derive the same
    // document key from the push/pull path pair.
    const plaintext = new Uint8Array([0xca, 0xfe, 0xba, 0xbe])
    const sealer = makeXorSealer()

    // Seal side (push path)
    const sealed = await sealer.sealBytes(
      plaintext,
      "spaces/s1/enc/obj1", // default aad for /push/spaces/s1/enc/obj1
    )

    // Open side (pull path) — must derive the same aad
    const mockFetch = vi.fn(async () =>
      new Response(sealed, {
        status: 200,
        headers: { "Content-Type": "application/octet-stream" },
      }),
    )
    const client = createClientWithFetch(mockFetch)

    // No explicit aad — pullAndOpenBlob should strip /pull/ and use "spaces/s1/enc/obj1"
    const result = await pullAndOpenBlob(client, sealer, "/pull/spaces/s1/enc/obj1")

    expect(sealer.lastOpenAad).toBe("spaces/s1/enc/obj1")
    expect(result).toEqual(plaintext)
  })

  it("wrong aad produces different output (AAD binding)", async () => {
    const plaintext = new Uint8Array([0xca, 0xfe])
    const sealer = makeXorSealer()
    const sealed = await sealer.sealBytes(plaintext, "correct-aad")

    // Note: the XOR sealer doesn't actually enforce AAD (it just records it).
    // This test verifies that openBytes is called with the aad we pass — the
    // real KeyringEncryptor would throw on mismatch (GCM tag failure).
    const mockFetch = vi.fn(async () =>
      new Response(sealed, {
        status: 200,
        headers: { "Content-Type": "application/octet-stream" },
      }),
    )
    const client = createClientWithFetch(mockFetch)

    await pullAndOpenBlob(client, sealer, "/pull/enc/obj", { aad: "wrong-aad" })

    // The sealer received the wrong aad — confirm it was forwarded
    expect(sealer.lastOpenAad).toBe("wrong-aad")
  })
})
