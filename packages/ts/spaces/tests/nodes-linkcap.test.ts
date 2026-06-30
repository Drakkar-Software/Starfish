/**
 * Regression tests for readNodeWithLinkCap / writeNodeWithLinkCap.
 *
 * L1: readNodeWithLinkCap hits objects/n/{nodeId}/content (not objects/{nodeId}/objinv)
 *     and returns the already-unwrapped json.data.
 * L2: 404 response → returns null (no throw).
 * L3: non-404 error → throws.
 * L4: writeNodeWithLinkCap POSTs to objects/n/{nodeId}/content.
 */
import { describe, it, expect, vi, beforeEach } from "vitest"
import { readNodeWithLinkCap, writeNodeWithLinkCap } from "../src/nodes.js"
import type { NodeInviteLinkToken } from "../src/token-types.js"

// Stub buildAuthHeaders so we don't need real cryptographic keys in tests.
vi.mock("../src/client.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/client.js")>()
  return {
    ...original,
    buildAuthHeaders: vi.fn(async () => ({ Authorization: "Bearer stub" })),
  }
})

const SPACE_ID = "sp-test"
const NODE_ID = "pub-test"

const STUB_TOKEN: NodeInviteLinkToken = {
  v: 1,
  spaceId: SPACE_ID,
  nodeId: NODE_ID,
  nodeName: "Test Page",
  cap: "stub-cap",
  key: "stub-key",
  write: false,
}

const OPTS = { baseUrl: "https://sync.example.com", namespace: "fiance" }

function mockFetch(status: number, body: unknown) {
  return vi.fn(async (_url: string) => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  }))
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe("readNodeWithLinkCap", () => {
  it("L1: requests objects/n/{nodeId}/content and returns unwrapped data", async () => {
    const payload = { about: { partner1Name: "Alice" } }
    const fetchSpy = mockFetch(200, { data: payload })
    vi.stubGlobal("fetch", fetchSpy)

    const result = await readNodeWithLinkCap(STUB_TOKEN, OPTS)

    expect(result).toEqual(payload)
    const [url] = fetchSpy.mock.calls[0]
    expect(url).toContain(`/objects/n/${NODE_ID}/content`)
    expect(url).not.toContain(`/objects/${NODE_ID}/objinv`)
  })

  it("L2: 404 response → returns null without throwing", async () => {
    vi.stubGlobal("fetch", mockFetch(404, {}))

    const result = await readNodeWithLinkCap(STUB_TOKEN, OPTS)

    expect(result).toBeNull()
  })

  it("L3: non-404 HTTP error → throws", async () => {
    vi.stubGlobal("fetch", mockFetch(500, {}))

    await expect(readNodeWithLinkCap(STUB_TOKEN, OPTS)).rejects.toThrow("readNodeWithLinkCap failed: HTTP 500")
  })
})

describe("writeNodeWithLinkCap", () => {
  it("L4: POSTs to objects/n/{nodeId}/content with baseHash:\"\" on first write", async () => {
    const fetchSpy = mockFetch(200, {})
    vi.stubGlobal("fetch", fetchSpy)

    await writeNodeWithLinkCap(STUB_TOKEN, { rsvpStatus: "ACCEPTED" }, OPTS)

    const [url, init] = fetchSpy.mock.calls[0]
    expect(url).toContain(`/objects/n/${NODE_ID}/content`)
    expect(url).not.toContain(`/objects/${NODE_ID}/objinv`)
    expect(init?.method).toBe("POST")
    const sentBody = JSON.parse(init?.body as string)
    expect(sentBody.baseHash).toBe("")
  })

  it("L5: 409 then 200 — adopts server currentHash and retries", async () => {
    const HASH = "abc123"
    let call = 0
    const fetchSpy = vi.fn(async () => {
      call++
      if (call === 1) {
        return { ok: false, status: 409, json: async () => ({ currentHash: HASH }) }
      }
      return { ok: true, status: 200, json: async () => ({}) }
    })
    vi.stubGlobal("fetch", fetchSpy)

    await writeNodeWithLinkCap(STUB_TOKEN, { rsvpStatus: "ACCEPTED" }, OPTS)

    expect(fetchSpy).toHaveBeenCalledTimes(2)
    const firstBody = JSON.parse(fetchSpy.mock.calls[0][1]?.body as string)
    expect(firstBody.baseHash).toBe("")
    const secondBody = JSON.parse(fetchSpy.mock.calls[1][1]?.body as string)
    expect(secondBody.baseHash).toBe(HASH)
  })

  it("L6: persistent 409 — throws after MAX_ATTEMPTS (3)", async () => {
    const fetchSpy = vi.fn(async () => ({
      ok: false,
      status: 409,
      json: async () => ({ currentHash: "stuck" }),
    }))
    vi.stubGlobal("fetch", fetchSpy)

    await expect(
      writeNodeWithLinkCap(STUB_TOKEN, { rsvpStatus: "ACCEPTED" }, OPTS),
    ).rejects.toThrow("writeNodeWithLinkCap: conflict after retries")

    expect(fetchSpy).toHaveBeenCalledTimes(3)
  })

  it("L7: non-409 HTTP error — throws immediately", async () => {
    vi.stubGlobal("fetch", mockFetch(403, {}))

    await expect(
      writeNodeWithLinkCap(STUB_TOKEN, { rsvpStatus: "ACCEPTED" }, OPTS),
    ).rejects.toThrow("writeNodeWithLinkCap failed: HTTP 403")
  })
})
