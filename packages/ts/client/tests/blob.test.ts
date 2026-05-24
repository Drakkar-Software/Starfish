import { describe, it, expect, vi } from "vitest"
import { StarfishClient } from "../src/client.js"
import { StarfishHttpError } from "../src/types.js"

function createClientWithFetch(mockFetch: typeof globalThis.fetch) {
  return new StarfishClient({
    baseUrl: "https://api.example.com/v1",
    fetch: mockFetch,
  })
}

describe("StarfishClient.pullBlob", () => {
  it("returns binary data with hash and content type", async () => {
    const binaryData = new Uint8Array([0x89, 0x50, 0x4e, 0x47]).buffer
    const mockFetch = vi.fn(async () => new Response(binaryData, {
      status: 200,
      headers: {
        "Content-Type": "image/png",
        "ETag": '"abc123hash"',
      },
    }))

    const client = createClientWithFetch(mockFetch)
    const result = await client.pullBlob("/pull/avatars/user1")

    expect(result.hash).toBe("abc123hash")
    expect(result.contentType).toBe("image/png")
    expect(result.data.byteLength).toBe(4)
  })

  it("defaults content type to application/octet-stream", async () => {
    const mockFetch = vi.fn(async () => new Response(new ArrayBuffer(0), {
      status: 200,
    }))

    const client = createClientWithFetch(mockFetch)
    const result = await client.pullBlob("/pull/blobs/x")

    expect(result.contentType).toBe("application/octet-stream")
  })

  it("throws StarfishHttpError on failure", async () => {
    const mockFetch = vi.fn(async () => new Response("not found", { status: 404 }))

    const client = createClientWithFetch(mockFetch)
    await expect(client.pullBlob("/pull/blobs/missing")).rejects.toThrow(StarfishHttpError)
  })

})

describe("StarfishClient.pushBlob", () => {
  it("sends binary data and returns hash", async () => {
    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify({ hash: "sha256hex" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    )

    const client = createClientWithFetch(mockFetch)
    const data = new Uint8Array([1, 2, 3, 4])
    const result = await client.pushBlob("/push/avatars/user1", data, "image/png")

    expect(result.hash).toBe("sha256hex")

    const [url, init] = mockFetch.mock.calls[0]
    expect(url).toBe("https://api.example.com/v1/push/avatars/user1")
    expect((init!.headers as Record<string, string>)["Content-Type"]).toBe("image/png")
  })

  it("accepts ArrayBuffer", async () => {
    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify({ hash: "h1" }), { status: 200 }),
    )

    const client = createClientWithFetch(mockFetch)
    const buf = new ArrayBuffer(8)
    const result = await client.pushBlob("/push/blobs/x", buf, "application/octet-stream")

    expect(result.hash).toBe("h1")
  })

  it("accepts Blob", async () => {
    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify({ hash: "h2" }), { status: 200 }),
    )

    const client = createClientWithFetch(mockFetch)
    const blob = new Blob(["hello"], { type: "text/plain" })
    const result = await client.pushBlob("/push/blobs/x", blob, "text/plain")

    expect(result.hash).toBe("h2")
  })

  it("throws StarfishHttpError on failure", async () => {
    const mockFetch = vi.fn(async () =>
      new Response("unsupported type", { status: 415 }),
    )

    const client = createClientWithFetch(mockFetch)
    await expect(
      client.pushBlob("/push/blobs/x", new ArrayBuffer(4), "video/mp4"),
    ).rejects.toThrow(StarfishHttpError)
  })
})
