/**
 * `createEventsProxyRouter`: authenticated SSE proxy. Covers 401 unauth,
 * 400 over maxCandidates, topic-cap truncation, the `__none__` sentinel when
 * nothing is authorized, id-charset rejection, and public open-gating. Mocks
 * the upstream `fetch` and the `authenticate` / `authorize` callbacks.
 */

import { describe, it, expect, vi, afterEach } from "vitest"
import { createEventsProxyRouter, type EventsProxyOptions } from "../src/events-proxy.js"

const UPSTREAM = "http://upstream.test/events"

/** Capture the topic= params from the single mocked upstream fetch call. */
function makeFetchMock(): { restore: () => void; topics: () => string[]; called: () => boolean } {
  let calledUrl: string | null = null
  const mock = vi.fn(async (url: string | URL) => {
    calledUrl = String(url)
    // A minimal readable stream body so `c.body(upstream.body)` succeeds.
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("data: ok\n\n"))
        controller.close()
      },
    })
    return new Response(body, { status: 200, headers: { "Content-Type": "text/event-stream" } })
  })
  vi.stubGlobal("fetch", mock)
  return {
    restore: () => vi.unstubAllGlobals(),
    called: () => calledUrl !== null,
    topics: () => {
      if (calledUrl === null) return []
      return new URL(calledUrl).searchParams.getAll("topic")
    },
  }
}

function buildApp(over: Partial<EventsProxyOptions>) {
  const opts: EventsProxyOptions = {
    authenticate: async () => "alice",
    candidatesParam: "ids",
    authorize: async () => false,
    topicMapper: (c) => [`topic-${c}`],
    upstreamUrl: UPSTREAM,
    maxCandidates: 16,
    maxTopics: 4,
    ...over,
  }
  return createEventsProxyRouter(opts)
}

afterEach(() => vi.unstubAllGlobals())

describe("createEventsProxyRouter", () => {
  it("401 when unauthenticated", async () => {
    const app = buildApp({ authenticate: async () => null })
    const res = await app.request("/events?ids=a,b")
    expect(res.status).toBe(401)
  })

  it("400 when over maxCandidates", async () => {
    const app = buildApp({ maxCandidates: 2 })
    const res = await app.request("/events?ids=a,b,c")
    expect(res.status).toBe(400)
  })

  it("truncates the authorized set at maxTopics", async () => {
    const fetchMock = makeFetchMock()
    const app = buildApp({ authorize: async () => true, maxTopics: 4 })
    const res = await app.request("/events?ids=p0,p1,p2,p3,p4,p5")
    expect(res.status).toBe(200)
    expect(fetchMock.topics()).toEqual(["topic-p0", "topic-p1", "topic-p2", "topic-p3"])
  })

  it("substitutes the __none__ sentinel when nothing is authorized", async () => {
    const fetchMock = makeFetchMock()
    const app = buildApp({ authorize: async () => false })
    const res = await app.request("/events?ids=a,b,c")
    expect(res.status).toBe(200)
    expect(fetchMock.topics()).toEqual(["__none__"])
  })

  it("rejects ids failing the charset pattern (even if authorized)", async () => {
    const fetchMock = makeFetchMock()
    // "bad id" has a space → fails DEFAULT_SAFE_ID; "good" passes.
    const app = buildApp({ authorize: async (_id, c) => c === "good" || c === "bad id" })
    const res = await app.request("/events?ids=good,bad id")
    expect(res.status).toBe(200)
    expect(fetchMock.topics()).toEqual(["topic-good"])
  })

  it("returns 502 when the upstream is not ok", async () => {
    const mock = vi.fn(async () => new Response(null, { status: 503 }))
    vi.stubGlobal("fetch", mock)
    const app = buildApp({ authorize: async () => true })
    const res = await app.request("/events?ids=a")
    expect(res.status).toBe(502)
  })

  it("drops a public candidate that fails the charset pattern", async () => {
    const fetchMock = makeFetchMock()
    // A PUBLIC candidate failing id_pattern must be dropped on the public branch
    // too, not just the authorize branch.
    const app = buildApp({ publicPredicate: (c) => c === "pub" || c === "bad pub" })
    const res = await app.request("/events?ids=pub,bad pub")
    expect(res.status).toBe(200)
    expect(fetchMock.topics()).toEqual(["topic-pub"])
  })

  it("open-gates public candidates without calling authorize", async () => {
    const fetchMock = makeFetchMock()
    const authorize = vi.fn(async () => false)
    const app = buildApp({ authorize, publicPredicate: (c) => c === "pub" })
    const res = await app.request("/events?ids=pub,priv")
    expect(res.status).toBe(200)
    expect(fetchMock.topics()).toEqual(["topic-pub"])
    // authorize is called only for the non-public "priv".
    expect(authorize).toHaveBeenCalledTimes(1)
    expect(authorize).toHaveBeenCalledWith("alice", "priv")
  })

  it("caps public-only fan-out but keeps private candidates that follow", async () => {
    const fetchMock = makeFetchMock()
    // The octochat scenario: cap the cheap-to-spoof public fan-out, but a private
    // candidate after the capped publics must still authorize.
    const app = buildApp({
      publicPredicate: (c) => c.startsWith("pub"),
      authorize: async (_id, c) => c === "priv1",
      maxTopics: 10,
      maxPublicTopics: 2,
    })
    const res = await app.request("/events?ids=pub1,pub2,pub3,priv1")
    expect(res.status).toBe(200)
    expect(fetchMock.topics()).toEqual(["topic-pub1", "topic-pub2", "topic-priv1"])
  })

  it("leaves public uncapped when maxPublicTopics is omitted", async () => {
    const fetchMock = makeFetchMock()
    const app = buildApp({ publicPredicate: () => true, maxTopics: 10 })
    const res = await app.request("/events?ids=a,b,c")
    expect(res.status).toBe(200)
    expect(fetchMock.topics().sort()).toEqual(["topic-a", "topic-b", "topic-c"])
  })

  it("maxTopics still bounds the total (public + private)", async () => {
    const fetchMock = makeFetchMock()
    const app = buildApp({
      publicPredicate: (c) => c === "pub1",
      authorize: async (_id, c) => c === "priv1" || c === "priv2",
      maxTopics: 2,
      maxPublicTopics: 10,
    })
    const res = await app.request("/events?ids=pub1,priv1,priv2")
    expect(res.status).toBe(200)
    expect(fetchMock.topics()).toEqual(["topic-pub1", "topic-priv1"])
  })
})
