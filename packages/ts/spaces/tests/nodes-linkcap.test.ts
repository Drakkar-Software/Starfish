/**
 * Regression tests for readNodeWithLinkCap / writeNodeWithLinkCap.
 *
 * L1: readNodeWithLinkCap hits objects/n/{nodeId}/content (not objects/{nodeId}/objinv)
 *     and returns the already-unwrapped json.data.
 * L2: 404 response → returns null (no throw).
 * L3: non-404 error → throws.
 * L4: writeNodeWithLinkCap POSTs to objects/n/{nodeId}/content.
 * L8: readNodeWithLinkCap signs with the namespaced path and real host (regression for
 *     the host:""/un-namespaced-path 401 bug).
 * L9: writeNodeWithLinkCap signs with the namespaced path, real host, and the JSON payload.
 */
import { describe, it, expect, vi, beforeEach } from "vitest"
import { readNodeWithLinkCap, writeNodeWithLinkCap } from "../src/nodes.js"
import { buildAuthHeaders } from "../src/client.js"
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

// ── Signing-regression tests ────────────────────────────────────────────────
// These lock the fix for the host:""/un-namespaced-path 401 bug.
// The server verifies against (host = real netloc, pathAndQuery = namespaced path).
// "buildAuthHeaders" is still mocked; we only check the ARGUMENTS it receives.

describe("request-signing: host + namespaced path (regression L8/L9)", () => {
  const EXPECTED_READ_PATH = `/v1/${OPTS.namespace}/pull/spaces/${SPACE_ID}/objects/n/${NODE_ID}/content`
  const EXPECTED_WRITE_PATH = `/v1/${OPTS.namespace}/push/spaces/${SPACE_ID}/objects/n/${NODE_ID}/content`
  const EXPECTED_HOST = new URL(OPTS.baseUrl).host // "sync.example.com"

  it("L8 read: buildAuthHeaders receives namespaced pathAndQuery and real host", async () => {
    vi.stubGlobal("fetch", mockFetch(200, { data: { ok: true } }))

    await readNodeWithLinkCap(STUB_TOKEN, OPTS)

    const mockBuild = vi.mocked(buildAuthHeaders)
    expect(mockBuild).toHaveBeenCalledOnce()
    const [, , method, pathAndQuery, host] = mockBuild.mock.calls[0]
    expect(method).toBe("GET")
    expect(pathAndQuery).toBe(EXPECTED_READ_PATH)
    expect(host).toBe(EXPECTED_HOST)
  })

  it("L8 read: fetch URL uses namespaced path (no signing mismatch)", async () => {
    const fetchSpy = mockFetch(200, { data: null })
    vi.stubGlobal("fetch", fetchSpy)

    await readNodeWithLinkCap(STUB_TOKEN, OPTS)

    const [url] = fetchSpy.mock.calls[0]
    expect(url).toBe(`${OPTS.baseUrl}${EXPECTED_READ_PATH}`)
  })

  it("L9 write: buildAuthHeaders receives namespaced path, real host, and JSON payload", async () => {
    vi.stubGlobal("fetch", mockFetch(200, {}))

    const data = { rsvpStatus: "ACCEPTED" }
    await writeNodeWithLinkCap(STUB_TOKEN, data, OPTS)

    const mockBuild = vi.mocked(buildAuthHeaders)
    expect(mockBuild).toHaveBeenCalledOnce()
    const [, , method, pathAndQuery, host, body] = mockBuild.mock.calls[0]
    expect(method).toBe("POST")
    expect(pathAndQuery).toBe(EXPECTED_WRITE_PATH)
    expect(host).toBe(EXPECTED_HOST)
    // body arg must be the exact JSON string sent over the wire
    expect(JSON.parse(body as string)).toEqual({ data, baseHash: "" })
  })

  it("L9 write: fetch URL uses namespaced path and body matches signed payload", async () => {
    const fetchSpy = mockFetch(200, {})
    vi.stubGlobal("fetch", fetchSpy)

    const data = { rsvpStatus: "ACCEPTED" }
    await writeNodeWithLinkCap(STUB_TOKEN, data, OPTS)

    const [url, init] = fetchSpy.mock.calls[0]
    expect(url).toBe(`${OPTS.baseUrl}${EXPECTED_WRITE_PATH}`)
    // The body sent to fetch must match the body passed to buildAuthHeaders.
    const mockBuild = vi.mocked(buildAuthHeaders)
    const signedBody = mockBuild.mock.calls[0][5]
    expect(init?.body).toBe(signedBody)
  })
})
