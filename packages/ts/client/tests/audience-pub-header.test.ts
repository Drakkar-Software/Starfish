import { describe, it, expect, vi, beforeAll } from "vitest"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { webcrypto } from "node:crypto"
import { StarfishClient } from "../src/client.js"

beforeAll(() => {
  configurePlatform({
    crypto: webcrypto as never,
    base64: {
      encode: (d: Uint8Array) => Buffer.from(d).toString("base64"),
      decode: (s: string) => new Uint8Array(Buffer.from(s, "base64")),
    },
  })
})

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  })
}

// The client only base64-encodes the cap for the header; it does not verify it,
// so a minimal stand-in suffices here.
const fakeCap = {
  v: 1,
  kind: "audience",
  iss: "aa".repeat(32),
  issUserId: "x",
  scope: { ops: ["read"], collections: ["c"] },
  nbf: 0,
  exp: 0,
  nonce: Buffer.from(new Uint8Array(16)).toString("base64"),
} as never

describe("StarfishClient X-Starfish-Pub emission", () => {
  it("emits X-Starfish-Pub when the provider returns pubHex (audience redemption)", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ data: {}, hash: "", timestamp: 0 }))
    const client = new StarfishClient({
      baseUrl: "http://t",
      fetch: fetchMock as never,
      capProvider: {
        getCap: async () => ({ cap: fakeCap, devEdPrivHex: "11".repeat(32), pubHex: "bb".repeat(32) }),
      },
    })
    await client.pull("/pull/c/x")
    const init = fetchMock.mock.calls[0]![1] as { headers: Record<string, string> }
    expect(init.headers["X-Starfish-Pub"]).toBe("bb".repeat(32))
    expect(init.headers["Authorization"]!.startsWith("Cap ")).toBe(true)
  })

  it("omits X-Starfish-Pub when the provider returns no pubHex (device/member)", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ data: {}, hash: "", timestamp: 0 }))
    const client = new StarfishClient({
      baseUrl: "http://t",
      fetch: fetchMock as never,
      capProvider: { getCap: async () => ({ cap: fakeCap, devEdPrivHex: "11".repeat(32) }) },
    })
    await client.pull("/pull/c/x")
    const init = fetchMock.mock.calls[0]![1] as { headers: Record<string, string> }
    expect("X-Starfish-Pub" in init.headers).toBe(false)
    expect(typeof init.headers["X-Starfish-Sig"]).toBe("string")
  })
})
