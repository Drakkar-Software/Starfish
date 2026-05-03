import { describe, it, expect, vi } from "vitest"
import { StarfishClient } from "../src/client.js"
import type { PushSuccess } from "@drakkar.software/starfish-protocol"

const PUSH_SUCCESS: PushSuccess = { hash: "abc123", timestamp: 1714000000 }

function mockFetch(data: unknown) {
  return vi.fn().mockResolvedValue({
    ok: true,
    json: async () => ({ data, hash: "h1", timestamp: 0 }),
  })
}

function makeClient(data: unknown) {
  return new StarfishClient({ baseUrl: "https://api.example.com/v1", fetch: mockFetch(data) })
}

describe("client.push with null baseHash (append-only)", () => {
  it("sends null baseHash in request body and returns PushSuccess", async () => {
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ hash: "abc123", timestamp: 1714000000 }),
    })
    const client = new StarfishClient({ baseUrl: "https://api.example.com/v1", fetch: fetchSpy })

    const result = await client.push("/push/events", { type: "click" }, null)

    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect(url).toBe("https://api.example.com/v1/push/events")
    expect(JSON.parse(init.body as string)).toMatchObject({ data: { type: "click" }, baseHash: null })
    expect(result).toEqual(PUSH_SUCCESS)
  })
})

describe("client.pull with AppendPullOptions", () => {
  it("returns data.items array", async () => {
    const result = await makeClient({ items: [{ msg: "a" }, { msg: "b" }] })
      .pull("/pull/events", { appendField: "items" })
    expect(result).toEqual([{ msg: "a" }, { msg: "b" }])
  })

  it("uses 'items' as default appendField when options object provided", async () => {
    const result = await makeClient({ items: [{ n: 1 }] })
      .pull("/pull/events", {})
    expect(result).toEqual([{ n: 1 }])
  })

  it("returns [] when data is null", async () => {
    const result = await makeClient(null).pull("/pull/events", { appendField: "items" })
    expect(result).toEqual([])
  })

  it("returns [] when field is absent", async () => {
    const result = await makeClient({}).pull("/pull/events", { appendField: "items" })
    expect(result).toEqual([])
  })

  it("returns [] when field is not an array", async () => {
    const result = await makeClient({ items: "not-an-array" })
      .pull("/pull/events", { appendField: "items" })
    expect(result).toEqual([])
  })

  it("supports custom appendField", async () => {
    const result = await makeClient({ logs: [{ x: 1 }] })
      .pull("/pull/events", { appendField: "logs" })
    expect(result).toEqual([{ x: 1 }])
  })

  it("sends ?checkpoint=<since> when since is provided", async () => {
    const fetchSpy = mockFetch({ items: [] })
    const c = new StarfishClient({ baseUrl: "https://api.example.com/v1", fetch: fetchSpy })

    await c.pull("/pull/events", { appendField: "items", since: 1714000000 })
    expect(fetchSpy).toHaveBeenCalledWith(
      "https://api.example.com/v1/pull/events?checkpoint=1714000000",
      expect.any(Object),
    )
  })

  it("sends ?last=<K> when last is provided", async () => {
    const fetchSpy = mockFetch({ items: [] })
    const c = new StarfishClient({ baseUrl: "https://api.example.com/v1", fetch: fetchSpy })

    await c.pull("/pull/events", { appendField: "items", last: 10 })
    expect(fetchSpy).toHaveBeenCalledWith(
      "https://api.example.com/v1/pull/events?last=10",
      expect.any(Object),
    )
  })

  it("combines since and last in query string", async () => {
    const fetchSpy = mockFetch({ items: [] })
    const c = new StarfishClient({ baseUrl: "https://api.example.com/v1", fetch: fetchSpy })

    await c.pull("/pull/logs", { appendField: "logs", since: 5000, last: 20 })
    expect(fetchSpy).toHaveBeenCalledWith(
      "https://api.example.com/v1/pull/logs?checkpoint=5000&last=20",
      expect.any(Object),
    )
  })

  it("no query params when since and last are omitted", async () => {
    const fetchSpy = mockFetch({ items: [] })
    const c = new StarfishClient({ baseUrl: "https://api.example.com/v1", fetch: fetchSpy })

    await c.pull("/pull/events", { appendField: "items" })
    expect(fetchSpy).toHaveBeenCalledWith(
      "https://api.example.com/v1/pull/events",
      expect.any(Object),
    )
  })

  it("standard pull (number checkpoint) still returns PullResult", async () => {
    const fetchSpy = mockFetch({ key: "value" })
    const c = new StarfishClient({ baseUrl: "https://api.example.com/v1", fetch: fetchSpy })

    const result = await c.pull("/pull/settings", 1000)
    expect(result).toHaveProperty("data", { key: "value" })
    expect(result).toHaveProperty("hash")
  })
})

describe("client.pull input validation", () => {
  it("throws when since is negative", async () => {
    const client = new StarfishClient({ baseUrl: "https://api.example.com/v1", fetch: vi.fn() })
    await expect(client.pull("/pull/events", { since: -1 })).rejects.toThrow("since must be non-negative")
  })

  it("throws when last is negative", async () => {
    const client = new StarfishClient({ baseUrl: "https://api.example.com/v1", fetch: vi.fn() })
    await expect(client.pull("/pull/events", { last: -1 })).rejects.toThrow("last must be non-negative")
  })
})
