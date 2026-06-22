/**
 * Tests for StarfishClient.appendAnonymous — cap-less public-write append.
 *
 * Uses a fixed test keypair (same technique as append-log.test.ts) to avoid
 * depending on @noble/curves in the client package's test devDependencies.
 */
import { describe, it, expect, vi } from "vitest"
import {
  verifyAppendAuthor,
  AUTHOR_PUBKEY_FIELD,
  AUTHOR_SIGNATURE_FIELD,
  DATA_FIELD,
} from "@drakkar.software/starfish-protocol"
import { StarfishClient, AppendHttpError } from "../src/index.js"

// A real Ed25519 keypair — same technique as append-log.test.ts.
const SIGNER = {
  edPrivHex: "1133557799bbddff1133557799bbddff1133557799bbddff1133557799bbddff",
  edPubHex: "062f2ba3c6a5590364b0864d539af151907d09ea0b741b0811e0d761a059bda4",
}

function makeSigner() {
  return SIGNER
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  })
}

describe("StarfishClient.appendAnonymous", () => {
  it("sends a POST with no Authorization header and a valid author proof", async () => {
    const signer = makeSigner()
    let capturedRequest: { url: string; init: RequestInit } | null = null

    const fetchMock = vi.fn(async (url: string, init: RequestInit) => {
      capturedRequest = { url, init }
      return jsonResponse({ timestamp: 1 })
    })

    const client = new StarfishClient({
      baseUrl: "https://api.example.com",
      fetch: fetchMock as unknown as typeof fetch,
    })

    const element = { type: "invite", payload: "abc" }
    await client.appendAnonymous("/push/inbox/user123/2024-06", element, signer)

    expect(capturedRequest).not.toBeNull()
    // No Authorization header.
    const headers = capturedRequest!.init.headers as Record<string, string>
    expect(headers["authorization"] ?? headers["Authorization"]).toBeUndefined()
    expect(headers["Authorization"]).toBeUndefined()

    // Body must contain data + author fields.
    const body = JSON.parse(capturedRequest!.init.body as string) as Record<string, unknown>
    expect(body[DATA_FIELD]).toEqual(element)
    expect(typeof body[AUTHOR_PUBKEY_FIELD]).toBe("string")
    expect(typeof body[AUTHOR_SIGNATURE_FIELD]).toBe("string")
  })

  it("produces an author proof that verifyAppendAuthor accepts", async () => {
    const signer = makeSigner()
    let capturedBody: Record<string, unknown> | null = null

    const fetchMock = vi.fn(async (_url: string, init: RequestInit) => {
      capturedBody = JSON.parse(init.body as string) as Record<string, unknown>
      return jsonResponse({ timestamp: 1 })
    })

    const client = new StarfishClient({
      baseUrl: "https://api.example.com",
      fetch: fetchMock as unknown as typeof fetch,
    })

    const element = { msg: "hello" }
    await client.appendAnonymous("/push/inbox/alice/2024-01", element, signer)

    // The server would verify the author proof like this:
    const documentKey = "inbox/alice/2024-01"
    const verified = await verifyAppendAuthor(
      documentKey,
      capturedBody![DATA_FIELD] as Record<string, unknown>,
      capturedBody![AUTHOR_PUBKEY_FIELD] as string,
      capturedBody![AUTHOR_SIGNATURE_FIELD] as string,
    )
    expect(verified).toBe(true)
  })

  it("respects the client namespace in the sent URL", async () => {
    const signer = makeSigner()
    let capturedUrl = ""

    const fetchMock = vi.fn(async (url: string) => {
      capturedUrl = url
      return jsonResponse({ timestamp: 1 })
    })

    const client = new StarfishClient({
      baseUrl: "https://api.example.com",
      namespace: "myapp",
      fetch: fetchMock as unknown as typeof fetch,
    })

    await client.appendAnonymous("/push/inbox/bob/2024-02", { x: 1 }, signer)

    expect(capturedUrl).toContain("/v1/myapp/push/")
  })

  it("throws AppendHttpError on a non-2xx response", async () => {
    const signer = makeSigner()
    const fetchMock = vi.fn(async () =>
      new Response("write_denied", { status: 403 }),
    )

    const client = new StarfishClient({
      baseUrl: "https://api.example.com",
      fetch: fetchMock as unknown as typeof fetch,
    })

    await expect(
      client.appendAnonymous("/push/public/col", { x: 1 }, signer),
    ).rejects.toThrow(AppendHttpError)

    try {
      await client.appendAnonymous("/push/public/col", { x: 1 }, signer)
    } catch (e) {
      expect(e).toBeInstanceOf(AppendHttpError)
      expect((e as AppendHttpError).status).toBe(403)
    }
  })

  it("does not attach a cap Authorization header even when the client has a capProvider", async () => {
    const signer = makeSigner()
    let capturedHeaders: Record<string, string> = {}

    const fetchMock = vi.fn(async (_url: string, init: RequestInit) => {
      capturedHeaders = init.headers as Record<string, string>
      return jsonResponse({ timestamp: 1 })
    })

    // Client has a cap provider — append() would sign with it.
    // appendAnonymous must NOT use it.
    const client = new StarfishClient({
      baseUrl: "https://api.example.com",
      fetch: fetchMock as unknown as typeof fetch,
      capProvider: {
        getCap: async () => ({
          cap: { sub: signer.edPubHex, kem: signer.edPubHex, kind: "device", scopes: [] } as never,
          devEdPrivHex: signer.edPrivHex,
        }),
      },
    })

    await client.appendAnonymous("/push/public/inbox", { y: 2 }, signer)
    expect(capturedHeaders["Authorization"] ?? capturedHeaders["authorization"]).toBeUndefined()
  })
})
