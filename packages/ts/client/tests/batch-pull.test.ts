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

  it("builds the collections + params query, signs it, and parses the response", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({
        collections: {
          profile: { data: { p: 1 }, hash: "h", timestamp: 1 },
          notes: { error: "Forbidden" },
        },
      }),
    ) as unknown as typeof fetch
    const client = new StarfishClient({ baseUrl: "https://host/v1", capProvider, fetch: fetchMock })

    const res = await client.batchPull(["profile", "notes"], { params: { notes: { teamId: "42" } } })

    // The fetched URL equals baseUrl + the canonical path the client signed —
    // so the bytes signed are exactly the bytes sent on the wire.
    const calledUrl = (fetchMock as ReturnType<typeof vi.fn>).mock.calls[0]![0] as string
    expect(calledUrl).toBe(`https://host/v1${signedPath()}`)
    expect(signRequestMock).toHaveBeenCalledTimes(1)

    // Decode the signed query: collections CSV + params as URL-encoded JSON.
    const signed = signedPath()
    expect(signed.startsWith("/batch/pull?")).toBe(true)
    const q = new URLSearchParams(signed.slice(signed.indexOf("?") + 1))
    expect(q.get("collections")).toBe("profile,notes")
    expect(JSON.parse(q.get("params")!)).toEqual({ notes: { teamId: "42" } })

    // Per-collection results are parsed through verbatim.
    expect(res.collections.profile.data).toEqual({ p: 1 })
    expect(res.collections.notes.error).toBe("Forbidden")
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
})
