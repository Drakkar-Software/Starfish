import { describe, it, expect, vi } from "vitest"
import { createDedupFetch } from "../src/dedup.js"

describe("createDedupFetch", () => {
  it("deduplicates concurrent identical GET requests", async () => {
    let callCount = 0
    const mockFetch = vi.fn(async () => {
      callCount++
      return new Response(JSON.stringify({ n: callCount }), {
        headers: { "Content-Type": "application/json" },
      })
    }) as unknown as typeof fetch

    const dedup = createDedupFetch(mockFetch)

    // Fire two identical GET requests concurrently
    const [r1, r2] = await Promise.all([
      dedup("https://api.example.com/data"),
      dedup("https://api.example.com/data"),
    ])

    // Only one actual fetch call
    expect(mockFetch).toHaveBeenCalledTimes(1)
    // Both get responses
    expect(r1.status).toBe(200)
    expect(r2.status).toBe(200)
  })

  it("does not deduplicate POST requests", async () => {
    const mockFetch = vi.fn(async () => new Response("ok")) as unknown as typeof fetch
    const dedup = createDedupFetch(mockFetch)

    await Promise.all([
      dedup("https://api.example.com/data", { method: "POST", body: "a" }),
      dedup("https://api.example.com/data", { method: "POST", body: "b" }),
    ])

    expect(mockFetch).toHaveBeenCalledTimes(2)
  })

  it("does not deduplicate different URLs", async () => {
    const mockFetch = vi.fn(async () => new Response("ok")) as unknown as typeof fetch
    const dedup = createDedupFetch(mockFetch)

    await Promise.all([
      dedup("https://api.example.com/a"),
      dedup("https://api.example.com/b"),
    ])

    expect(mockFetch).toHaveBeenCalledTimes(2)
  })

  it("allows new requests after previous completes", async () => {
    const mockFetch = vi.fn(async () => new Response("ok")) as unknown as typeof fetch
    const dedup = createDedupFetch(mockFetch)

    await dedup("https://api.example.com/data")
    await dedup("https://api.example.com/data")

    // Sequential requests are not deduped
    expect(mockFetch).toHaveBeenCalledTimes(2)
  })

  it("handles fetch errors without breaking dedup", async () => {
    let callCount = 0
    const mockFetch = vi.fn(async () => {
      callCount++
      if (callCount === 1) throw new Error("network error")
      return new Response("ok")
    }) as unknown as typeof fetch

    const dedup = createDedupFetch(mockFetch)

    await expect(dedup("https://api.example.com/data")).rejects.toThrow("network error")
    // After error, URL is cleared from cache
    const res = await dedup("https://api.example.com/data")
    expect(res.status).toBe(200)
  })
})
