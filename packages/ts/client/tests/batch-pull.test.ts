import { describe, it, expect, vi, beforeEach } from "vitest"

// Stub `signRequest` so we can observe the canonical path the client SIGNS
// (auth integrity), with no real crypto. See namespace.test.ts for the rationale.
vi.mock("@drakkar.software/starfish-protocol", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@drakkar.software/starfish-protocol")>()
  return {
    ...actual,
    signRequest: vi.fn(async () => ({ alg: "ed25519", sig: "stub-sig", ts: 1, nonce: "stub-nonce" })),
  }
})

import { StarfishClient } from "../src/client.js"
import { signRequest } from "@drakkar.software/starfish-protocol"

const signRequestMock = vi.mocked(signRequest)

const PRIV = "1".repeat(64)
const CAP = { kind: "device", iss: "issuer", issAlg: "ed25519", subAlg: "ed25519" }
const capProvider = { getCap: async () => ({ cap: CAP as never, devEdPrivHex: PRIV }) }

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } })
}

/** The path-and-query the client handed the signer for the one request under test. */
function signedPath(): string {
  return signRequestMock.mock.calls[0]![0].pathAndQuery
}

describe("StarfishClient.batchPull", () => {
  beforeEach(() => signRequestMock.mockClear())

  it("builds the collections + array-params query, signs it, and parses the array response", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({
        collections: {
          // `profile` fanned in two documents; `notes` one (denied).
          profile: [
            { data: { p: 1 }, hash: "h1", timestamp: 1 },
            { data: { p: 2 }, hash: "h2", timestamp: 2 },
          ],
          notes: [{ error: "Forbidden" }],
        },
      }),
    ) as unknown as typeof fetch
    const client = new StarfishClient({ baseUrl: "https://host/v1", capProvider, fetch: fetchMock })

    const res = await client.batchPull(["profile", "notes"], {
      params: { profile: [{ identity: "a" }, { identity: "b" }], notes: [{ teamId: "42" }] },
    })

    // The fetched URL equals baseUrl + the canonical path the client signed —
    // so the bytes signed are exactly the bytes sent on the wire.
    const calledUrl = (fetchMock as ReturnType<typeof vi.fn>).mock.calls[0]![0] as string
    expect(calledUrl).toBe(`https://host/v1${signedPath()}`)
    expect(signRequestMock).toHaveBeenCalledTimes(1)

    // Decode the signed query: collections CSV + params as URL-encoded JSON, now
    // an array of param-sets per collection.
    const signed = signedPath()
    expect(signed.startsWith("/batch/pull?")).toBe(true)
    const q = new URLSearchParams(signed.slice(signed.indexOf("?") + 1))
    expect(q.get("collections")).toBe("profile,notes")
    expect(JSON.parse(q.get("params")!)).toEqual({
      profile: [{ identity: "a" }, { identity: "b" }],
      notes: [{ teamId: "42" }],
    })

    // Per-document results are parsed through verbatim, in order.
    expect(res.collections.profile.map((e) => e.data)).toEqual([{ p: 1 }, { p: 2 }])
    expect(res.collections.notes[0]!.error).toBe("Forbidden")
  })

  it("omits the params query when none is supplied, and honors the namespace", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ collections: {} })) as unknown as typeof fetch
    const client = new StarfishClient({
      baseUrl: "https://host/sync",
      namespace: "octochat",
      capProvider,
      fetch: fetchMock,
    })

    await client.batchPull(["settings", "notes"])

    const calledUrl = (fetchMock as ReturnType<typeof vi.fn>).mock.calls[0]![0] as string
    expect(calledUrl).toBe(`https://host/sync${signedPath()}`)
    // Namespace is inserted before the query, and `params` is absent.
    expect(signedPath()).toBe("/v1/octochat/batch/pull?collections=settings%2Cnotes")
  })

  describe("batchPullMany", () => {
    it("reads many docs of one collection and returns the entries in input order", async () => {
      const fetchMock = vi.fn(async () =>
        jsonResponse({
          collections: {
            profile: [
              { data: { pseudo: "a" }, hash: "h1", timestamp: 1 },
              { error: "Forbidden" },
              { data: { pseudo: "c" }, hash: "h3", timestamp: 3 },
            ],
          },
        }),
      ) as unknown as typeof fetch
      const client = new StarfishClient({ baseUrl: "https://host/v1", capProvider, fetch: fetchMock })

      const entries = await client.batchPullMany("profile", [
        { identity: "a" },
        { identity: "b" },
        { identity: "c" },
      ])

      // One round-trip; the array aligns 1:1 with the requested param-sets.
      expect(signRequestMock).toHaveBeenCalledTimes(1)
      const q = new URLSearchParams(signedPath().slice(signedPath().indexOf("?") + 1))
      expect(q.get("collections")).toBe("profile")
      expect(JSON.parse(q.get("params")!)).toEqual({
        profile: [{ identity: "a" }, { identity: "b" }, { identity: "c" }],
      })
      expect(entries).toHaveLength(3)
      expect(entries[0]!.data).toEqual({ pseudo: "a" })
      expect(entries[1]!.error).toBe("Forbidden")
      expect(entries[2]!.data).toEqual({ pseudo: "c" })
    })

    it("issues no request for an empty param list", async () => {
      const fetchMock = vi.fn() as unknown as typeof fetch
      const client = new StarfishClient({ baseUrl: "https://host/v1", capProvider, fetch: fetchMock })

      const entries = await client.batchPullMany("profile", [])

      expect(entries).toEqual([])
      expect(fetchMock as ReturnType<typeof vi.fn>).not.toHaveBeenCalled()
    })
  })
})
