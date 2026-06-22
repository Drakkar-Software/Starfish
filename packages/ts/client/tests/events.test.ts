/**
 * Tests for the SSE client helpers: parseSseFrames, buildSignedEventsUrl,
 * and subscribeChanges.
 */
import { describe, it, expect, vi, afterEach } from "vitest"
import { parseSseFrames, buildSignedEventsUrl, subscribeChanges } from "../src/events.js"

// ── parseSseFrames ────────────────────────────────────────────────────────────

describe("parseSseFrames", () => {
  it("parses a single complete frame", () => {
    const { events, carry } = parseSseFrames('data: hello\n\n', "")
    expect(events).toEqual(["hello"])
    expect(carry).toBe("")
  })

  it("parses multiple frames in one chunk", () => {
    const chunk = "data: a\n\ndata: b\n\n"
    const { events } = parseSseFrames(chunk, "")
    expect(events).toEqual(["a", "b"])
  })

  it("holds an incomplete frame as carry", () => {
    const { events, carry } = parseSseFrames("data: hel", "")
    expect(events).toHaveLength(0)
    expect(carry).toBe("data: hel")
  })

  it("combines carry with the next chunk to complete a frame", () => {
    const { carry: c1 } = parseSseFrames("data: hel", "")
    const { events, carry: c2 } = parseSseFrames("lo\n\n", c1)
    expect(events).toEqual(["hello"])
    expect(c2).toBe("")
  })

  it("skips id:, event:, retry:, and comment lines", () => {
    const chunk = "id: 42\nevent: update\nretry: 3000\n: heartbeat\ndata: payload\n\n"
    const { events } = parseSseFrames(chunk, "")
    expect(events).toEqual(["payload"])
  })

  it("joins multi-line data: into a single event with \\n", () => {
    const chunk = "data: line1\ndata: line2\n\n"
    const { events } = parseSseFrames(chunk, "")
    expect(events).toEqual(["line1\nline2"])
  })

  it("normalises \\r\\n line endings", () => {
    const chunk = "data: hello\r\n\r\n"
    const { events } = parseSseFrames(chunk, "")
    expect(events).toEqual(["hello"])
  })

  it("normalises \\r line endings", () => {
    const chunk = "data: hello\r\rdata: world\r\r"
    const { events } = parseSseFrames(chunk, "")
    expect(events).toEqual(["hello", "world"])
  })

  it("trims the leading space after data:", () => {
    const { events } = parseSseFrames("data: padded\n\n", "")
    expect(events).toEqual(["padded"])
  })

  it("does not trim when there is no space after data:", () => {
    // Per SSE spec, `: ` means strip exactly one leading space.
    const { events } = parseSseFrames("data:no-space\n\n", "")
    expect(events).toEqual(["no-space"])
  })

  it("handles a frame split across exactly the blank-line boundary", () => {
    const { carry: c1 } = parseSseFrames("data: value\n", "")
    const { events } = parseSseFrames("\n", c1)
    expect(events).toEqual(["value"])
  })

  it("returns no events for an empty string", () => {
    const { events, carry } = parseSseFrames("", "")
    expect(events).toHaveLength(0)
    expect(carry).toBe("")
  })
})

// ── buildSignedEventsUrl ──────────────────────────────────────────────────────

describe("buildSignedEventsUrl", () => {
  it("returns the URL as-is when no mountBase or params given", () => {
    const { url, pathAndQuery } = buildSignedEventsUrl("https://api.example.com/events")
    expect(url).toBe("https://api.example.com/events")
    expect(pathAndQuery).toBe("/events")
  })

  it("adds query params", () => {
    const { url, pathAndQuery } = buildSignedEventsUrl("https://api.example.com/events", {
      ns: "myapp",
    })
    expect(url).toContain("ns=myapp")
    expect(pathAndQuery).toContain("ns=myapp")
  })

  it("strips the mountBase pathname from the signed path", () => {
    // The server is mounted at /sync, nginx strips /sync before forwarding.
    const { url, pathAndQuery } = buildSignedEventsUrl(
      "https://api.example.com/sync/events",
      undefined,
      "https://api.example.com/sync",
    )
    // Signed path should be just /events (without /sync prefix).
    expect(pathAndQuery).toBe("/events")
    // Fetch URL still has the full path.
    expect(url).toContain("/sync/events")
  })

  it("percent-encodes comma in query values (prevents CDN re-encoding)", () => {
    const { url, pathAndQuery } = buildSignedEventsUrl("https://api.example.com/events", {
      spaces: "sp-a,sp-b",
    })
    // URLSearchParams encodes comma as %2C.
    expect(url).toContain("spaces=sp-a%2Csp-b")
    expect(pathAndQuery).toContain("spaces=sp-a%2Csp-b")
  })

  it("handles mountBase without trailing slash", () => {
    const { pathAndQuery } = buildSignedEventsUrl(
      "https://api.example.com/api/v1/events",
      undefined,
      "https://api.example.com/api/v1",
    )
    expect(pathAndQuery).toBe("/events")
  })
})

// ── subscribeChanges ──────────────────────────────────────────────────────────

/** Build a mock fetch that returns a streaming SSE response. */
function makeSseResponse(frames: string[], delay = 0): Response {
  const encoder = new TextEncoder()
  const chunks = frames.map((f) => encoder.encode(`data: ${f}\n\n`))
  let idx = 0
  const readable = new ReadableStream<Uint8Array>({
    async pull(ctrl) {
      if (delay) await new Promise<void>((r) => setTimeout(r, delay))
      if (idx < chunks.length) {
        ctrl.enqueue(chunks[idx++]!)
      } else {
        ctrl.close()
      }
    },
  })
  return new Response(readable, {
    status: 200,
    headers: { "content-type": "text/event-stream" },
  })
}

describe("subscribeChanges", () => {
  afterEach(() => vi.restoreAllMocks())

  it("delivers parsed changes via onChange", async () => {
    const received: string[] = []
    const fetchMock = vi.fn().mockResolvedValueOnce(makeSseResponse(["alpha", "beta", "gamma"]))

    globalThis.fetch = fetchMock as unknown as typeof fetch

    await new Promise<void>((resolve) => {
      let count = 0
      const unsub = subscribeChanges({
        url: "https://api.example.com/events",
        authHeaders: async () => ({}),
        parse: (d) => d,
        onChange: (c) => {
          received.push(c)
          if (++count === 3) {
            unsub()
            resolve()
          }
        },
      })
    })

    expect(received).toEqual(["alpha", "beta", "gamma"])
  })

  it("fires onStatus(true) on connect and onStatus(false) on disconnect", async () => {
    const statuses: boolean[] = []
    const fetchMock = vi.fn().mockResolvedValueOnce(makeSseResponse(["x"]))

    globalThis.fetch = fetchMock as unknown as typeof fetch

    await new Promise<void>((resolve) => {
      const unsub = subscribeChanges({
        url: "https://api.example.com/events",
        authHeaders: async () => ({}),
        parse: (d) => d,
        onChange: () => {
          unsub()
        },
        onStatus: (s) => {
          statuses.push(s)
          if (!s) resolve()
        },
      })
    })

    expect(statuses[0]).toBe(true)
    expect(statuses[statuses.length - 1]).toBe(false)
  })

  it("calls url factory on every reconnect attempt", async () => {
    const urls: string[] = []
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new TypeError("network error"))
      .mockResolvedValueOnce(makeSseResponse(["ok"]))

    globalThis.fetch = fetchMock as unknown as typeof fetch

    let calls = 0
    await new Promise<void>((resolve) => {
      const unsub = subscribeChanges({
        url: () => {
          const u = `https://api.example.com/events?attempt=${calls}`
          urls.push(u)
          return u
        },
        authHeaders: async () => ({}),
        parse: (d) => d,
        onChange: () => {
          unsub()
          resolve()
        },
        minReconnectMs: 10,
        maxReconnectMs: 100,
      })
      calls++
    })

    // url factory called at least twice (once per attempt).
    expect(urls.length).toBeGreaterThanOrEqual(2)
  })

  it("stops reconnecting after unsub() is called", async () => {
    let fetchCount = 0
    const fetchMock = vi.fn().mockImplementation(() => {
      fetchCount++
      return Promise.reject(new TypeError("network error"))
    })

    globalThis.fetch = fetchMock as unknown as typeof fetch

    const unsub = subscribeChanges({
      url: "https://api.example.com/events",
      authHeaders: async () => ({}),
      parse: () => null,
      onChange: () => {},
      minReconnectMs: 10,
      maxReconnectMs: 50,
    })

    await new Promise<void>((r) => setTimeout(r, 80))
    const countBeforeUnsub = fetchCount
    unsub()
    await new Promise<void>((r) => setTimeout(r, 80))
    // After unsub no further fetch calls should have been made.
    expect(fetchCount).toBe(countBeforeUnsub)
  })
})
