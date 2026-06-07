import { describe, it, expect, vi } from "vitest"
import { createReplicaAuth } from "../src/auth.js"
import {
  configurePlatform,
  verifyRequestSignature,
  type RequestSignature,
} from "@drakkar.software/starfish-protocol"
import {
  bootstrapRootIdentity,
  mintDeviceCap,
  scopes,
} from "@drakkar.software/starfish-identities"
import { webcrypto } from "node:crypto"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

const PASSPHRASE = "correct horse battery staple"

function decodeCapHeader(header: string): Record<string, unknown> {
  expect(header.startsWith("Cap ")).toBe(true)
  const json = Buffer.from(header.slice("Cap ".length), "base64").toString("utf-8")
  return JSON.parse(json)
}

describe("createReplicaAuth", () => {
  it("signs the request and attaches cap + signature headers", async () => {
    const creds = await bootstrapRootIdentity(PASSPHRASE)
    let captured: Request | undefined
    const underlying = vi.fn(async (input: any, init: any) => {
      captured = new Request(input, init)
      return new Response(JSON.stringify({ ok: true }), { status: 200 })
    }) as unknown as typeof fetch

    const auth = await createReplicaAuth({ credentials: creds, fetchFn: underlying })
    await auth.fetch(
      "https://primary.example.com:8443/v1/ns/pull/posts/x?a=1",
    )

    expect(captured).toBeDefined()
    const req = captured!
    const sig = req.headers.get("X-Starfish-Sig")!
    const ts = req.headers.get("X-Starfish-Ts")!
    const nonce = req.headers.get("X-Starfish-Nonce")!
    const authHeader = req.headers.get("Authorization")!

    expect(sig).toBeTruthy()
    expect(ts).toBeTruthy()
    expect(nonce).toBeTruthy()

    const cap = decodeCapHeader(authHeader)
    expect(cap["sub"]).toBe(creds.device.edPub)

    const signature: RequestSignature = { sig, ts: Number(ts), nonce }
    const ok = await verifyRequestSignature(
      {
        method: "GET",
        pathAndQuery: "/v1/ns/pull/posts/x?a=1",
        body: "",
        host: "primary.example.com:8443",
      },
      signature,
      creds.device.edPub,
    )
    expect(ok).toBe(true)
  })

  it("folds POST body bytes into the signature", async () => {
    const creds = await bootstrapRootIdentity(PASSPHRASE)
    let captured: { req: Request; body: string } | undefined
    const underlying = vi.fn(async (input: any, init: any) => {
      const r = new Request(input, init)
      captured = { req: r, body: await r.clone().text() }
      return new Response(JSON.stringify({ hash: "abc" }), { status: 200 })
    }) as unknown as typeof fetch

    const auth = await createReplicaAuth({ credentials: creds, fetchFn: underlying })
    const body = JSON.stringify({ data: { k: "v" } })
    await auth.fetch("https://primary.example.com/v1/ns/push/p", {
      method: "POST",
      body,
    })

    const req = captured!.req
    const sig: RequestSignature = {
      sig: req.headers.get("X-Starfish-Sig")!,
      ts: Number(req.headers.get("X-Starfish-Ts")!),
      nonce: req.headers.get("X-Starfish-Nonce")!,
    }
    const good = await verifyRequestSignature(
      { method: "POST", pathAndQuery: "/v1/ns/push/p", body, host: "primary.example.com" },
      sig,
      creds.device.edPub,
    )
    expect(good).toBe(true)

    const tampered = await verifyRequestSignature(
      { method: "POST", pathAndQuery: "/v1/ns/push/p", body: "tampered", host: "primary.example.com" },
      sig,
      creds.device.edPub,
    )
    expect(tampered).toBe(false)
  })

  it("bootstraps from a passphrase and exposes userId", async () => {
    const auth = await createReplicaAuth({ passphrase: PASSPHRASE })
    const creds = await bootstrapRootIdentity(PASSPHRASE)
    expect(auth.userId).toBe(creds.userId)
  })

  it("requires exactly one of passphrase / credentials", async () => {
    await expect(createReplicaAuth({})).rejects.toThrow()
    const creds = await bootstrapRootIdentity(PASSPHRASE)
    await expect(
      createReplicaAuth({ passphrase: PASSPHRASE, credentials: creds }),
    ).rejects.toThrow()
  })

  it("auto-refreshes the cap when near expiry", async () => {
    const creds = await bootstrapRootIdentity(PASSPHRASE)
    // Short-lived cap so refresh triggers.
    const shortCap = await mintDeviceCap(
      creds.device.edPriv,
      creds.device.edPub,
      { edPubHex: creds.device.edPub, kemPubHex: creds.device.kemPub },
      scopes.rootAll(),
      { ttlSec: 10 },
    )
    const shortCreds = { ...creds, capCert: shortCap }

    const underlying = vi.fn(async () => new Response("{}", { status: 200 })) as unknown as typeof fetch
    const auth = await createReplicaAuth({
      credentials: shortCreds,
      refreshMarginSec: 24 * 3600, // margin >> 10s TTL → always refresh
      clock: () => shortCap.exp - 5, // just inside the refresh margin
      fetchFn: underlying,
    })

    let captured: Request | undefined
    const captureFetch = vi.fn(async (input: any, init: any) => {
      captured = new Request(input, init)
      return new Response("{}", { status: 200 })
    }) as unknown as typeof fetch
    // Re-create with the capturing fetch so we observe the refreshed cap header.
    const auth2 = await createReplicaAuth({
      credentials: shortCreds,
      refreshMarginSec: 24 * 3600,
      clock: () => shortCap.exp - 5,
      fetchFn: captureFetch,
    })

    await auth2.fetch("https://primary.example.com/v1/ns/pull/x")

    const cap = decodeCapHeader(captured!.headers.get("Authorization")!)
    // The freshly minted cap (default 30d TTL) expires later than the short cap.
    expect(Number(cap["exp"])).toBeGreaterThan(shortCap.exp)
    expect(cap["sub"]).toBe(creds.device.edPub)
    void auth
  })

  it("reuses a fresh cap without re-minting", async () => {
    const creds = await bootstrapRootIdentity(PASSPHRASE) // default 30d TTL
    let captured: Request | undefined
    const underlying = vi.fn(async (input: any, init: any) => {
      captured = new Request(input, init)
      return new Response("{}", { status: 200 })
    }) as unknown as typeof fetch
    const auth = await createReplicaAuth({
      credentials: creds,
      refreshMarginSec: 3600,
      fetchFn: underlying,
    })

    await auth.fetch("https://primary.example.com/v1/ns/pull/x")

    const cap = decodeCapHeader(captured!.headers.get("Authorization")!)
    // Unchanged cap → same exp as the bootstrapped cap.
    expect(Number(cap["exp"])).toBe(creds.capCert.exp)
  })
})
