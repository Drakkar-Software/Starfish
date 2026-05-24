import { describe, it, expect, vi } from "vitest"
import { StarfishClient } from "../src/client.js"

function makeJsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  })
}

describe("StarfishClient.pull withKeyring option", () => {
  it("does not add ?withKeyring when option omitted", async () => {
    const fetchMock = vi.fn(async () => makeJsonResponse({
      data: { _encrypted: "ct" },
      hash: "h",
      timestamp: 1,
    }))
    const client = new StarfishClient({ baseUrl: "http://t", fetch: fetchMock as any })

    await client.pull("/pull/notes/abc")

    const url = fetchMock.mock.calls[0]![0] as string
    expect(url).toBe("http://t/pull/notes/abc")
    expect(url).not.toContain("withKeyring")
  })

  it("appends ?withKeyring=1 when withKeyring=true", async () => {
    const fetchMock = vi.fn(async () => makeJsonResponse({
      data: { _encrypted: "ct" },
      hash: "h",
      timestamp: 1,
      keyring: { data: { v: 1, currentEpoch: 1 }, hash: "kh", timestamp: 1 },
    }))
    const client = new StarfishClient({ baseUrl: "http://t", fetch: fetchMock as any })

    const result = await client.pull("/pull/notes/abc", { withKeyring: true })

    const url = fetchMock.mock.calls[0]![0] as string
    expect(url).toBe("http://t/pull/notes/abc?withKeyring=1")
    // Result preserves the keyring field passed through from server.
    expect((result as any).keyring).toEqual({
      data: { v: 1, currentEpoch: 1 },
      hash: "kh",
      timestamp: 1,
    })
  })

  it("withKeyring=false produces a plain URL", async () => {
    const fetchMock = vi.fn(async () => makeJsonResponse({
      data: {}, hash: "", timestamp: 0,
    }))
    const client = new StarfishClient({ baseUrl: "http://t", fetch: fetchMock as any })

    await client.pull("/pull/notes/abc", { withKeyring: false })

    const url = fetchMock.mock.calls[0]![0] as string
    expect(url).toBe("http://t/pull/notes/abc")
  })

  it("withKeyring composes with checkpoint", async () => {
    const fetchMock = vi.fn(async () => makeJsonResponse({
      data: {}, hash: "", timestamp: 0,
    }))
    const client = new StarfishClient({ baseUrl: "http://t", fetch: fetchMock as any })

    await client.pull("/pull/notes/abc", { checkpoint: 100, withKeyring: true })

    const url = fetchMock.mock.calls[0]![0] as string
    expect(url).toContain("checkpoint=100")
    expect(url).toContain("withKeyring=1")
  })

  it("withKeyring=true with keyring:null is returned verbatim", async () => {
    const fetchMock = vi.fn(async () => makeJsonResponse({
      data: { _encrypted: "ct" }, hash: "h", timestamp: 1, keyring: null,
    }))
    const client = new StarfishClient({ baseUrl: "http://t", fetch: fetchMock as any })

    const result = await client.pull("/pull/notes/abc", { withKeyring: true })
    expect((result as any).keyring).toBeNull()
  })

  it("existing numeric-checkpoint signature still works", async () => {
    const fetchMock = vi.fn(async () => makeJsonResponse({
      data: {}, hash: "", timestamp: 0,
    }))
    const client = new StarfishClient({ baseUrl: "http://t", fetch: fetchMock as any })

    await client.pull("/pull/notes/abc", 500)

    const url = fetchMock.mock.calls[0]![0] as string
    expect(url).toBe("http://t/pull/notes/abc?checkpoint=500")
  })
})
