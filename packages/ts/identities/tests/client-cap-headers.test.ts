/**
 * v3.0 cap-cert request signing — wire-format tests for `StarfishClient`.
 *
 * When a `capProvider` is set, every authenticated request must carry:
 *   - Authorization: Cap <base64(stableStringify(cap))>
 *   - X-Starfish-Sig:   base64 Ed25519 signature
 *   - X-Starfish-Ts:    unix ms (decimal string)
 *   - X-Starfish-Nonce: base64 nonce
 *
 * The signature must validate against the cap's subject pubkey when replayed
 * through `verifyRequestSignature`. Configuring both `auth` and `capProvider`
 * is rejected at construction time.
 */
import { describe, it, expect, vi } from "vitest"
import {
  stableStringify,
  verifyRequestSignature,
  type Alg,
  type SignableMethod,
} from "@drakkar.software/starfish-protocol"
import { StarfishClient } from "@drakkar.software/starfish-client"
import type { StarfishCapProvider } from "@drakkar.software/starfish-client"
import { deriveRootIdentity } from "../src/identity.js"
import { mintDeviceCap, scopes } from "../src/cap-mint.js"

function b64decode(s: string): Uint8Array {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
}

async function makeLaptopCap() {
  const alice = await deriveRootIdentity("alice-root-passphrase")
  const laptop = await deriveRootIdentity("alice-laptop")
  const cap = await mintDeviceCap(
    alice.keys.edPriv,
    alice.keys.edPub,
    { edPubHex: laptop.keys.edPub, kemPubHex: laptop.keys.kemPub },
    scopes.rootAll(),
  )
  return { cap, devEdPrivHex: laptop.keys.edPriv, devEdPubHex: laptop.keys.edPub }
}

describe("StarfishClient cap-cert request signing", () => {
  it("attaches Cap auth + sig/ts/nonce headers on every push request", async () => {
    const { cap, devEdPrivHex, devEdPubHex } = await makeLaptopCap()

    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ hash: "h", timestamp: 1 }),
    })

    const capProvider: StarfishCapProvider = {
      getCap: async () => ({ cap, devEdPrivHex }),
    }

    const client = new StarfishClient({
      baseUrl: "https://api.example.com/v1",
      fetch: fetchSpy,
      capProvider,
    })

    await client.push("/push/test", { foo: "bar" }, null)

    expect(fetchSpy).toHaveBeenCalledTimes(1)
    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
    const headers = init.headers as Record<string, string>

    expect(headers.Authorization).toMatch(/^Cap /)
    expect(headers["X-Starfish-Sig"]).toBeTruthy()
    expect(headers["X-Starfish-Ts"]).toMatch(/^\d+$/)
    expect(headers["X-Starfish-Nonce"]).toBeTruthy()

    // Decode + verify: parse cap, decode signature triplet, replay verifier.
    const capJson = new TextDecoder().decode(
      b64decode(headers.Authorization.slice("Cap ".length)),
    )
    const parsedCap = JSON.parse(capJson)
    expect(parsedCap.sub).toBe(devEdPubHex)

    const ts = parseInt(headers["X-Starfish-Ts"], 10)
    const signature = {
      alg: headers["X-Starfish-Alg"] as Alg,
      sig: headers["X-Starfish-Sig"],
      ts,
      nonce: headers["X-Starfish-Nonce"],
    }
    const ok = await verifyRequestSignature(
      {
        method: "POST" as SignableMethod,
        pathAndQuery: "/push/test",
        body: init.body as string,
        host: "api.example.com",
      },
      signature,
      devEdPubHex,
    )
    expect(ok).toBe(true)
  })

  it("attaches Cap headers on pull as well", async () => {
    const { cap, devEdPrivHex, devEdPubHex } = await makeLaptopCap()
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ data: { x: 1 }, hash: "h", timestamp: 1 }),
    })
    const client = new StarfishClient({
      baseUrl: "https://api.example.com/v1",
      fetch: fetchSpy,
      capProvider: { getCap: async () => ({ cap, devEdPrivHex }) },
    })
    await client.pull("/pull/test", 0)
    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
    const headers = init.headers as Record<string, string>
    expect(headers.Authorization).toMatch(/^Cap /)
    const ok = await verifyRequestSignature(
      {
        method: "GET" as SignableMethod,
        pathAndQuery: "/pull/test",
        body: undefined,
        host: "api.example.com",
      },
      {
        alg: headers["X-Starfish-Alg"] as Alg,
        sig: headers["X-Starfish-Sig"],
        ts: parseInt(headers["X-Starfish-Ts"], 10),
        nonce: headers["X-Starfish-Nonce"],
      },
      devEdPubHex,
    )
    expect(ok).toBe(true)
  })

  it("includes the query string in the signed pathAndQuery for pull with checkpoint", async () => {
    const { cap, devEdPrivHex, devEdPubHex } = await makeLaptopCap()
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ data: {}, hash: "h", timestamp: 1 }),
    })
    const client = new StarfishClient({
      baseUrl: "https://api.example.com/v1",
      fetch: fetchSpy,
      capProvider: { getCap: async () => ({ cap, devEdPrivHex }) },
    })
    await client.pull("/pull/test", 42)

    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect(url).toBe("https://api.example.com/v1/pull/test?checkpoint=42")
    const headers = init.headers as Record<string, string>
    const ok = await verifyRequestSignature(
      {
        method: "GET" as SignableMethod,
        pathAndQuery: "/pull/test?checkpoint=42",
        body: undefined,
        host: "api.example.com",
      },
      {
        alg: headers["X-Starfish-Alg"] as Alg,
        sig: headers["X-Starfish-Sig"],
        ts: parseInt(headers["X-Starfish-Ts"], 10),
        nonce: headers["X-Starfish-Nonce"],
      },
      devEdPubHex,
    )
    expect(ok).toBe(true)
  })

  it("encodes the cap as base64 of its canonical stableStringify", async () => {
    const { cap, devEdPrivHex } = await makeLaptopCap()
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ data: {}, hash: "h", timestamp: 1 }),
    })
    const client = new StarfishClient({
      baseUrl: "https://api.example.com/v1",
      fetch: fetchSpy,
      capProvider: { getCap: async () => ({ cap, devEdPrivHex }) },
    })
    await client.pull("/pull/test", 0)
    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
    const headers = init.headers as Record<string, string>
    const expected = btoa(stableStringify(cap as unknown as Record<string, unknown>))
    expect(headers.Authorization).toBe(`Cap ${expected}`)
  })

  it("does not add Cap headers when capProvider is not set", async () => {
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ data: {}, hash: "h", timestamp: 1 }),
    })
    const client = new StarfishClient({
      baseUrl: "https://api.example.com/v1",
      fetch: fetchSpy,
    })
    await client.pull("/pull/test", 0)
    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
    const headers = init.headers as Record<string, string>
    expect(headers.Authorization).toBeUndefined()
    expect(headers["X-Starfish-Sig"]).toBeUndefined()
    expect(headers["X-Starfish-Ts"]).toBeUndefined()
    expect(headers["X-Starfish-Nonce"]).toBeUndefined()
  })
})
