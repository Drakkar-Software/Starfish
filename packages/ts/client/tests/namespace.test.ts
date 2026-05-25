import { describe, it, expect, vi, beforeEach } from "vitest"

// Replace `signRequest` with a recording stub that returns a fixed signature.
// The point is to assert the canonical path the client SIGNS — not merely the
// URL it hits: a client that namespaced the URL but signed the bare path would
// fail auth against a namespace-mounted server (which reconstructs the canonical
// from the namespaced URL). Observing the stub's `pathAndQuery` argument captures
// exactly that, with no real crypto. `...actual` keeps the rest of the protocol
// module intact (the client also uses `stableStringify`, `DEFAULT_ALG`, …).
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

// The cap provider must supply a private key; its value is irrelevant because
// `signRequest` is stubbed (no real signing). A syntactically valid 32-byte hex.
const PRIV = "1".repeat(64)
const CAP = { kind: "device", iss: "issuer", issAlg: "ed25519", subAlg: "ed25519" }
const capProvider = { getCap: async () => ({ cap: CAP as never, devEdPrivHex: PRIV }) }

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  })
}

/** The path-and-query the client handed the signer for the request under test.
 *  Each test issues exactly one request, so the client's call is `calls[0]`. */
function signedPath(): string {
  return signRequestMock.mock.calls[0]![0].pathAndQuery
}

function makeFetch(body: unknown = { data: {}, hash: "h", timestamp: 1 }) {
  return vi.fn(async () => jsonResponse(body)) as unknown as typeof fetch
}

describe("StarfishClient namespace", () => {
  beforeEach(() => signRequestMock.mockClear())

  it("pull: rewrites BOTH the URL and the signed canonical path", async () => {
    const fetchMock = makeFetch()
    const client = new StarfishClient({
      baseUrl: "https://host/sync",
      namespace: "octochat",
      capProvider,
      fetch: fetchMock,
    })

    await client.pull("/pull/spaces/x/_keyring")

    // Exactly one signed request per operation (no extra/duplicate signing).
    expect(signRequestMock).toHaveBeenCalledTimes(1)
    expect((fetchMock as ReturnType<typeof vi.fn>).mock.calls[0]![0]).toBe(
      "https://host/sync/v1/octochat/pull/spaces/x/_keyring",
    )
    // The key assertion: the signed canonical includes the namespace + /v1 …
    expect(signedPath()).toBe("/v1/octochat/pull/spaces/x/_keyring")
    // … and is NOT the bare path (what a URL-only namespacer would have signed).
    expect(signedPath()).not.toBe("/pull/spaces/x/_keyring")
  })

  it("pull: namespace is inserted before the query string", async () => {
    const fetchMock = makeFetch()
    const client = new StarfishClient({
      baseUrl: "https://host/sync",
      namespace: "octochat",
      capProvider,
      fetch: fetchMock,
    })

    await client.pull("/pull/spaces/x", { checkpoint: 42 })

    expect((fetchMock as ReturnType<typeof vi.fn>).mock.calls[0]![0]).toBe(
      "https://host/sync/v1/octochat/pull/spaces/x?checkpoint=42",
    )
    expect(signedPath()).toBe("/v1/octochat/pull/spaces/x?checkpoint=42")
  })

  it("push: rewrites URL + signed path", async () => {
    const fetchMock = makeFetch()
    const client = new StarfishClient({
      baseUrl: "https://host/sync",
      namespace: "octochat",
      capProvider,
      fetch: fetchMock,
    })

    await client.push("/push/spaces/x", { a: 1 }, null)

    expect((fetchMock as ReturnType<typeof vi.fn>).mock.calls[0]![0]).toBe(
      "https://host/sync/v1/octochat/push/spaces/x",
    )
    expect(signedPath()).toBe("/v1/octochat/push/spaces/x")
  })

  it("append: rewrites URL + signed path", async () => {
    const fetchMock = makeFetch()
    const client = new StarfishClient({
      baseUrl: "https://host/sync",
      namespace: "octochat",
      capProvider,
      fetch: fetchMock,
    })

    await client.append("/push/streams/x", { t: "msg" })

    expect((fetchMock as ReturnType<typeof vi.fn>).mock.calls[0]![0]).toBe(
      "https://host/sync/v1/octochat/push/streams/x",
    )
    expect(signedPath()).toBe("/v1/octochat/push/streams/x")
  })

  it("pushBlob: rewrites URL + signed path (the SDK-helper-built-path case)", async () => {
    const fetchMock = makeFetch({ hash: "h" })
    const client = new StarfishClient({
      baseUrl: "https://host/sync",
      namespace: "octochat",
      capProvider,
      fetch: fetchMock,
    })

    await client.pushBlob("/push/attachments/x", new Uint8Array([1, 2, 3]), "application/octet-stream")

    expect((fetchMock as ReturnType<typeof vi.fn>).mock.calls[0]![0]).toBe(
      "https://host/sync/v1/octochat/push/attachments/x",
    )
    expect(signedPath()).toBe("/v1/octochat/push/attachments/x")
  })

  it("pullBlob: rewrites URL + signed path", async () => {
    const fetchMock = vi.fn(async () => new Response(new Uint8Array([1]).buffer, { status: 200 })) as unknown as typeof fetch
    const client = new StarfishClient({
      baseUrl: "https://host/sync",
      namespace: "octochat",
      capProvider,
      fetch: fetchMock,
    })

    await client.pullBlob("/pull/attachments/x")

    expect((fetchMock as ReturnType<typeof vi.fn>).mock.calls[0]![0]).toBe(
      "https://host/sync/v1/octochat/pull/attachments/x",
    )
    expect(signedPath()).toBe("/v1/octochat/pull/attachments/x")
  })

  it("no namespace: URL and signed path are unchanged (backward compatible)", async () => {
    const fetchMock = makeFetch()
    const client = new StarfishClient({
      baseUrl: "https://host/v1",
      capProvider,
      fetch: fetchMock,
    })

    await client.pull("/pull/spaces/x")

    expect((fetchMock as ReturnType<typeof vi.fn>).mock.calls[0]![0]).toBe("https://host/v1/pull/spaces/x")
    expect(signedPath()).toBe("/pull/spaces/x")
  })

  it("empty-string namespace is treated as unset", async () => {
    const fetchMock = makeFetch()
    const client = new StarfishClient({
      baseUrl: "https://host/v1",
      namespace: "",
      capProvider,
      fetch: fetchMock,
    })

    await client.pull("/pull/spaces/x")

    expect((fetchMock as ReturnType<typeof vi.fn>).mock.calls[0]![0]).toBe("https://host/v1/pull/spaces/x")
    expect(signedPath()).toBe("/pull/spaces/x")
  })
})
