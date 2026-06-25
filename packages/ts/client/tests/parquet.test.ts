import { describe, it, expect, vi } from "vitest"
import { StarfishClient } from "../src/client.js"
import { PARQUET_MIME_TYPE, PARQUET_MIME_TYPES } from "../src/index.js"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PARQUET_BYTES = new Uint8Array([0x50, 0x41, 0x52, 0x31, 0x00, 0x00]) // "PAR1\x00\x00"

function makeClient(fetchFn: typeof fetch): StarfishClient {
  return new StarfishClient({
    baseUrl: "https://api.example.com/v1",
    fetch: fetchFn as any,
  })
}

// ---------------------------------------------------------------------------
// Re-export constants
// ---------------------------------------------------------------------------

describe("PARQUET_MIME_TYPE / PARQUET_MIME_TYPES (client re-exports)", () => {
  it("PARQUET_MIME_TYPE is the canonical vnd MIME string", () => {
    expect(PARQUET_MIME_TYPE).toBe("application/vnd.apache.parquet")
  })

  it("PARQUET_MIME_TYPES contains all three variants", () => {
    expect(PARQUET_MIME_TYPES).toContain("application/vnd.apache.parquet")
    expect(PARQUET_MIME_TYPES).toContain("application/x-parquet")
    expect(PARQUET_MIME_TYPES).toContain("application/octet-stream")
  })
})

// ---------------------------------------------------------------------------
// pushParquet
// ---------------------------------------------------------------------------

describe("StarfishClient.pushParquet", () => {
  it("sends Content-Type: application/vnd.apache.parquet", async () => {
    const capturedHeaders: Record<string, string> = {}

    const fetchFn = vi.fn(async (url: string, init?: RequestInit) => {
      for (const [k, v] of Object.entries(init?.headers as Record<string, string> ?? {})) {
        capturedHeaders[k.toLowerCase()] = v
      }
      return new Response(JSON.stringify({ hash: "abc123" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    })

    const client = makeClient(fetchFn as any)
    await client.pushParquet("/push/analytics/alice/q1.parquet", PARQUET_BYTES)

    expect(capturedHeaders["content-type"]).toBe("application/vnd.apache.parquet")
  })

  it("posts to the correct URL path", async () => {
    let capturedUrl = ""

    const fetchFn = vi.fn(async (url: string) => {
      capturedUrl = url
      return new Response(JSON.stringify({ hash: "abc" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    })

    const client = makeClient(fetchFn as any)
    await client.pushParquet("/push/analytics/alice/q1.parquet", PARQUET_BYTES)

    expect(capturedUrl).toBe("https://api.example.com/v1/push/analytics/alice/q1.parquet")
  })

  it("returns BlobPushResult with hash", async () => {
    const fetchFn = vi.fn(async () =>
      new Response(JSON.stringify({ hash: "deadbeef" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    )

    const client = makeClient(fetchFn as any)
    const result = await client.pushParquet("/push/analytics/alice/q1.parquet", PARQUET_BYTES)
    expect(result.hash).toBe("deadbeef")
  })

  it("throws StarfishHttpError on non-200", async () => {
    const fetchFn = vi.fn(async () =>
      new Response("forbidden", { status: 403 }),
    )

    const client = makeClient(fetchFn as any)
    await expect(
      client.pushParquet("/push/analytics/alice/q1.parquet", PARQUET_BYTES),
    ).rejects.toMatchObject({ status: 403 })
  })
})

// ---------------------------------------------------------------------------
// pullParquet
// ---------------------------------------------------------------------------

describe("StarfishClient.pullParquet", () => {
  it("makes a GET request to the correct URL", async () => {
    let capturedUrl = ""

    const fetchFn = vi.fn(async (url: string) => {
      capturedUrl = url
      return new Response(PARQUET_BYTES, {
        status: 200,
        headers: {
          "Content-Type": PARQUET_MIME_TYPE,
          ETag: '"abc123"',
        },
      })
    })

    const client = makeClient(fetchFn as any)
    await client.pullParquet("/pull/analytics/alice/q1.parquet")
    expect(capturedUrl).toBe("https://api.example.com/v1/pull/analytics/alice/q1.parquet")
  })

  it("returns BlobPullResult with data, hash, and contentType", async () => {
    const fetchFn = vi.fn(async () =>
      new Response(PARQUET_BYTES, {
        status: 200,
        headers: {
          "Content-Type": PARQUET_MIME_TYPE,
          ETag: '"abc123"',
        },
      }),
    )

    const client = makeClient(fetchFn as any)
    const result = await client.pullParquet("/pull/analytics/alice/q1.parquet")
    expect(result.contentType).toBe(PARQUET_MIME_TYPE)
    expect(result.hash).toBe("abc123")
    expect(result.data.byteLength).toBe(PARQUET_BYTES.byteLength)
  })

  it("throws StarfishHttpError on non-200", async () => {
    const fetchFn = vi.fn(async () => new Response("not found", { status: 404 }))
    const client = makeClient(fetchFn as any)
    await expect(client.pullParquet("/pull/analytics/alice/missing.parquet")).rejects.toMatchObject({
      status: 404,
    })
  })
})
