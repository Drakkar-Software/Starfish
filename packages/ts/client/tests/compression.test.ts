import { describe, it, expect, vi } from "vitest"
import { createCompressedFetch } from "../src/fetch.js"

// CompressionStream may not be available in all Node.js test environments
const hasCompressionStream = typeof globalThis.CompressionStream !== "undefined"

describe("createCompressedFetch", () => {
  it("passes through requests without body unchanged", async () => {
    const inner = vi.fn(async () => new Response("ok", { status: 200 }))
    const compressedFetch = createCompressedFetch(inner)

    const res = await compressedFetch("https://example.com", { method: "GET" })

    expect(res.status).toBe(200)
    expect(inner).toHaveBeenCalledTimes(1)
    const [, init] = inner.mock.calls[0]
    expect(init?.headers).toBeUndefined()
  })

  it.skipIf(!hasCompressionStream)(
    "compresses string body and adds Content-Encoding header",
    async () => {
      const inner = vi.fn(async () => new Response("ok", { status: 200 }))
      const compressedFetch = createCompressedFetch(inner)

      const body = JSON.stringify({ key: "value", nested: { a: 1, b: 2 } })
      await compressedFetch("https://example.com", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
      })

      expect(inner).toHaveBeenCalledTimes(1)
      const [, init] = inner.mock.calls[0]
      const headers = init!.headers as Record<string, string>
      expect(headers["content-encoding"]).toBe("gzip")
      expect(headers["content-type"]).toBe("application/json")
      expect(init!.body).toBeInstanceOf(ArrayBuffer)
    },
  )

  it("falls back to uncompressed when CompressionStream is unavailable", async () => {
    const origCS = globalThis.CompressionStream
    // @ts-expect-error - removing for test
    delete globalThis.CompressionStream

    const inner = vi.fn(async () => new Response("ok", { status: 200 }))
    const compressedFetch = createCompressedFetch(inner)

    await compressedFetch("https://example.com", {
      method: "POST",
      body: '{"test": true}',
    })

    const [, init] = inner.mock.calls[0]
    expect(init!.body).toBe('{"test": true}')

    if (origCS) globalThis.CompressionStream = origCS
  })

  it("uses global fetch when no inner fetch provided", async () => {
    const mockGlobalFetch = vi.fn(async () => new Response("ok", { status: 200 }))
    vi.stubGlobal("fetch", mockGlobalFetch)

    const compressedFetch = createCompressedFetch()
    await compressedFetch("https://example.com", { method: "GET" })

    expect(mockGlobalFetch).toHaveBeenCalledTimes(1)
    vi.unstubAllGlobals()
  })
})
