import { describe, it, expect, beforeAll } from "vitest"
import { ed25519, x25519 } from "@noble/curves/ed25519.js"
import { sha256 } from "@noble/hashes/sha2.js"
import {
  configurePlatform,
  signCapCert,
  signRequest,
  type UnsignedCapCert,
  type CapCert,
  type SignableRequest,
} from "@drakkar.software/starfish-protocol"
import { webcrypto } from "node:crypto"
import { sharingServerPlugin } from "@drakkar.software/starfish-sharing"
import { createCapCertRoleResolver } from "../../src/router/cap-resolver.js"
import { createInMemoryNonceCache } from "../../src/auth/nonce-cache.js"
import { createInMemoryRevocationStore } from "../../src/auth/revocation-store.js"

beforeAll(() => {
  configurePlatform({
    crypto: webcrypto as any,
    base64: {
      encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
      decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
    },
  })
})

function bytesToHex(b: Uint8Array): string {
  let s = ""
  for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, "0")
  return s
}

interface RootKeys {
  edPriv: Uint8Array
  edPub: Uint8Array
  edPubHex: string
  userId: string
  kemPub: Uint8Array
  kemPubHex: string
}

function makeRoot(seed: number): RootKeys {
  const edPriv = new Uint8Array(32).fill(seed)
  const edPub = ed25519.getPublicKey(edPriv)
  const edPubHex = bytesToHex(edPub)
  const userId = bytesToHex(sha256(edPub)).slice(0, 32)
  // X25519 KEM key reuse — for test purposes we generate a deterministic one
  const kemPriv = new Uint8Array(32).fill(seed + 1)
  const kemPub = x25519.getPublicKey(kemPriv)
  return { edPriv, edPub, edPubHex, userId, kemPub, kemPubHex: bytesToHex(kemPub) }
}

async function mintDeviceCertForTest(
  issuer: RootKeys,
  subject: RootKeys,
  nbf: number,
  ttlSec = 3600,
): Promise<CapCert> {
  const unsigned: UnsignedCapCert = {
    v: 1,
    kind: "device",

    iss: issuer.edPubHex,
    issUserId: issuer.userId,
    sub: subject.edPubHex,
    subKem: subject.kemPubHex,
    scope: {
      ops: ["read", "write", "list"],
      collections: ["notes"],
      paths: ["notes/*"],
    },
    nbf,
    exp: nbf + ttlSec,
    nonce: Buffer.from(new Uint8Array(16).fill(7)).toString("base64"),
  }
  return signCapCert(unsigned, bytesToHex(issuer.edPriv))
}

async function mintMemberCertForTest(
  issuer: RootKeys,
  subject: RootKeys,
  nbf: number,
  ttlSec = 3600,
): Promise<CapCert> {
  const unsigned: UnsignedCapCert = {
    v: 1,
    kind: "member",

    iss: issuer.edPubHex,
    issUserId: issuer.userId,
    sub: subject.edPubHex,
    subKem: subject.kemPubHex,
    subUserId: subject.userId,
    scope: {
      ops: ["read", "write"],
      collections: ["shared"],
      paths: ["shared/{identity}/*"],
    },
    nbf,
    exp: nbf + ttlSec,
    nonce: Buffer.from(new Uint8Array(16).fill(3)).toString("base64"),
  }
  return signCapCert(unsigned, bytesToHex(issuer.edPriv))
}

interface FakeReqHeaders {
  [k: string]: string
}

function fakeContext(opts: {
  method: string
  url: string
  headers?: FakeReqHeaders
  body?: Uint8Array
}): any {
  const headers = new Map<string, string>(
    Object.entries(opts.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
  )
  const bodyBytes = opts.body ?? new Uint8Array(0)
  return {
    req: {
      url: opts.url,
      method: opts.method,
      header(name?: string): string | undefined | Record<string, string> {
        if (name === undefined) {
          return Object.fromEntries(headers.entries())
        }
        return headers.get(name.toLowerCase())
      },
      async arrayBuffer(): Promise<ArrayBuffer> {
        return bodyBytes.buffer.slice(
          bodyBytes.byteOffset,
          bodyBytes.byteOffset + bodyBytes.byteLength,
        ) as ArrayBuffer
      },
      async text(): Promise<string> {
        return new TextDecoder().decode(bodyBytes)
      },
    },
  }
}

describe("createCapCertRoleResolver", () => {
  it("returns identity=issUserId and cap roles for a valid device cap", async () => {
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const cert = await mintDeviceCertForTest(alice, dev, nowSec - 10)

    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })

    const url = "https://api.example.com/push/notes/abc"
    const req: SignableRequest = {
      method: "POST",
      pathAndQuery: "/push/notes/abc",
      body: new TextEncoder().encode("{}"),
      host: "api.example.com",
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")
    const c = fakeContext({
      method: "POST",
      url,
      body: new TextEncoder().encode("{}"),
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
        "Content-Length": "2",
      },
    })
    const auth = await resolver(c)
    expect(auth.identity).toBe(alice.userId)
    expect(auth.roles).toContain("cap:write:notes")
    expect(auth.roles).toContain("cap:read:notes")
    expect(auth.roles).toContain("cap:list:notes")
    // `self` is NOT emitted by the resolver — the route-builder adds it
    // conditionally on `params.identity === auth.identity`. The path here
    // has no `{identity}` param, so `self` must be absent.
    expect(auth.roles).not.toContain("self")
  })

  it("verifies a non-JSON (blob) POST whose body bytes are not covered by the signature", async () => {
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const cert = await mintDeviceCertForTest(alice, dev, nowSec - 10)
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })

    // Blob uploads are signed with an EMPTY body — the client's `pushBlob`
    // passes `body: undefined`, since clients don't fold large/streamed blob
    // bytes into the per-request signature (blob integrity comes from the
    // content seal, not the request sig).
    const req: SignableRequest = {
      method: "POST",
      pathAndQuery: "/push/notes/blob1",
      body: undefined,
      host: "api.example.com",
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")
    // The actual ciphertext rides on the wire unsigned (octet-stream).
    const blob = new Uint8Array([0, 0, 0, 1, 9, 8, 7, 6, 5, 4, 3, 2, 1])
    const c = fakeContext({
      method: "POST",
      url: "https://api.example.com/push/notes/blob1",
      body: blob,
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
        "Content-Type": "application/octet-stream",
        "Content-Length": String(blob.length),
      },
    })
    const auth = await resolver(c)
    expect(auth.identity).toBe(alice.userId)
    expect(auth.roles).toContain("cap:write:notes")
  })

  it("verifies a non-octet binary (image/png) blob signed with an empty body", async () => {
    // The client signs ANY blob with an empty body, not just octet-stream — so the
    // server treats any non-JSON content type as a blob upload. Mirrors test_cap_resolver.py.
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const cert = await mintDeviceCertForTest(alice, dev, Math.floor(Date.now() / 1000) - 10)
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    const req: SignableRequest = {
      method: "POST",
      pathAndQuery: "/push/notes/avatar",
      body: undefined, // empty-body signature
      host: "api.example.com",
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")
    const blob = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]) // PNG magic
    const c = fakeContext({
      method: "POST",
      url: "https://api.example.com/push/notes/avatar",
      body: blob,
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
        "Content-Type": "image/png",
        "Content-Length": String(blob.length),
      },
    })
    const auth = await resolver(c)
    expect(auth.identity).toBe(alice.userId)
    expect(auth.roles).toContain("cap:write:notes")
  })

  it("rejects a non-integer X-Starfish-Ts identically to the Python int() parse", async () => {
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const cert = await mintDeviceCertForTest(alice, dev, nowSec - 10)
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")
    // JS Number() would accept all of these (16, 1000, 12.5, 12); Python's
    // int() rejects them. The resolver must reject them on both runtimes,
    // before the clock-skew gate, with the same error.
    for (const badTs of ["0x10", "1e3", "12.5", " 12"]) {
      const c = fakeContext({
        method: "POST",
        url: "https://api.example.com/push/notes/abc",
        body: new TextEncoder().encode("{}"),
        headers: {
          Authorization: `Cap ${certB64}`,
          "X-Starfish-Sig": "AA",
          "X-Starfish-Ts": badTs,
          "X-Starfish-Nonce": "AA",
          "Content-Length": "2",
        },
      })
      await expect(resolver(c)).rejects.toThrow("invalid X-Starfish-Ts")
    }
  })

  it("rejects a validly-signed request whose X-Starfish-Ts is non-ASCII digits", async () => {
    // Arabic-Indic digits parse to the SAME integer under Python's Unicode-aware
    // \d + int(), so a transcoded Ts authenticates there; JS's ASCII-only \d
    // rejects it at parse, before the skew gate. This pins the TS (reference) side
    // of that divergence — the Python twin is an xfail in test_cap_resolver.py
    // (test_unicode_digit_timestamp_rejected_identically_to_typescript).
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const cert = await mintDeviceCertForTest(alice, dev, nowSec - 10)
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    const req: SignableRequest = {
      method: "POST",
      pathAndQuery: "/push/notes/abc",
      body: new TextEncoder().encode("{}"),
      host: "api.example.com",
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const toArabicIndic = (s: string): string => s.replace(/[0-9]/g, (d) => "٠١٢٣٤٥٦٧٨٩"[Number(d)]!)
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")
    const c = fakeContext({
      method: "POST",
      url: "https://api.example.com/push/notes/abc",
      body: new TextEncoder().encode("{}"),
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": toArabicIndic(String(sig.ts)),
        "X-Starfish-Nonce": sig.nonce,
        "Content-Length": "2",
      },
    })
    await expect(resolver(c)).rejects.toThrow("invalid X-Starfish-Ts")
  })

  it("returns anonymous (public) when Authorization is missing and allowAnonymous=true", async () => {
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
      allowAnonymous: true,
    })
    const c = fakeContext({ method: "GET", url: "https://x/y" })
    const auth = await resolver(c)
    expect(auth.identity).toBe("")
    expect(auth.roles).toEqual(["public"])
  })

  it("throws 401 when Authorization is missing and allowAnonymous=false", async () => {
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
      allowAnonymous: false,
    })
    const c = fakeContext({ method: "GET", url: "https://x/y" })
    await expect(resolver(c)).rejects.toMatchObject({ status: 401 })
  })

  it("throws 401 when cap signature is invalid", async () => {
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const cert = await mintDeviceCertForTest(alice, dev, nowSec - 10)
    // Tamper with signature
    const bad = { ...cert, sig: Buffer.from(new Uint8Array(64)).toString("base64") }
    const certB64 = Buffer.from(JSON.stringify(bad)).toString("base64")

    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    const c = fakeContext({
      method: "GET",
      url: "https://api/foo",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": "x",
        "X-Starfish-Ts": String(Date.now()),
        "X-Starfish-Nonce": "n",
      },
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 401 })
  })

  it("throws 401 when the request signature is invalid", async () => {
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const cert = await mintDeviceCertForTest(alice, dev, nowSec - 10)
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")

    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    const c = fakeContext({
      method: "GET",
      url: "https://api/foo",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": Buffer.from(new Uint8Array(64)).toString("base64"),
        "X-Starfish-Ts": String(Date.now()),
        "X-Starfish-Nonce": Buffer.from(new Uint8Array(16)).toString("base64"),
      },
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 401 })
  })

  it("throws 401 on replayed nonce", async () => {
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const cert = await mintDeviceCertForTest(alice, dev, nowSec - 10)
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })

    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: "/pull/notes/abc",
      body: undefined,
      host: "api",
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const headers = {
      Authorization: `Cap ${certB64}`,
      "X-Starfish-Sig": sig.sig,
      "X-Starfish-Ts": String(sig.ts),
      "X-Starfish-Nonce": sig.nonce,
    }

    const c1 = fakeContext({ method: "GET", url: "https://api/pull/notes/abc", headers })
    const auth1 = await resolver(c1)
    expect(auth1.identity).toBe(alice.userId)

    const c2 = fakeContext({ method: "GET", url: "https://api/pull/notes/abc", headers })
    await expect(resolver(c2)).rejects.toMatchObject({ status: 401 })
  })

  it("throws 401 when cap is expired", async () => {
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    // nbf far in the past, ttl tiny → expired by now (with default 300s skew, we need to be > 300s past)
    const nbf = Math.floor(Date.now() / 1000) - 100_000
    const cert = await mintDeviceCertForTest(alice, dev, nbf, 10)
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")

    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: "/pull/notes/x",
      body: undefined,
      host: "api",
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/x",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
      },
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 401 })
  })

  it("returns subUserId and delegated:<issUserId> roles for a member cap", async () => {
    const alice = makeRoot(0x42)
    const bob = makeRoot(0x99)
    const nowSec = Math.floor(Date.now() / 1000)
    const cert = await mintMemberCertForTest(alice, bob, nowSec - 10)
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")

    // The member cap's scope.paths is `shared/{identity}/*` and `{identity}`
    // is expanded server-side to `bob.userId`. The URL must hit that path.
    const reqPath = `/pull/shared/${bob.userId}/abc`
    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: reqPath,
      body: undefined,
      host: "api",
    }
    const sig = await signRequest(req, bytesToHex(bob.edPriv))
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
      // member caps require a registered validator (device-only by default).
      plugins: [sharingServerPlugin],
    })
    const c = fakeContext({
      method: "GET",
      url: `https://api${reqPath}`,
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
      },
    })
    const auth = await resolver(c)
    expect(auth.identity).toBe(bob.userId)
    expect(auth.roles).toContain(`delegated:${alice.userId}:shared`)
    expect(auth.roles).toContain("cap:read:shared")
    expect(auth.roles).toContain("cap:write:shared")
  })

  // --- pre-auth body buffer (DoS amplifier) ---

  it("rejects 413 when Content-Length exceeds maxBodyBytes BEFORE buffering body", async () => {
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const cert = await mintDeviceCertForTest(alice, dev, nowSec - 10)
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })

    // arrayBuffer() will throw — if the resolver attempts to read the body it
    // means the up-front Content-Length check was skipped.
    const url = "https://api/push/notes/abc"
    let arrayBufferCalled = false
    const c: any = {
      req: {
        url,
        method: "POST",
        header(name?: string) {
          const headers: Record<string, string> = {
            authorization: `Cap ${certB64}`,
            "x-starfish-sig": "x",
            "x-starfish-ts": String(Date.now()),
            "x-starfish-nonce": "n",
            "content-length": "100000000",
          }
          if (name === undefined) return headers
          return headers[name.toLowerCase()]
        },
        async arrayBuffer() {
          arrayBufferCalled = true
          return new Uint8Array(0).buffer
        },
      },
    }
    await expect(resolver(c)).rejects.toMatchObject({ status: 413 })
    expect(arrayBufferCalled).toBe(false)
  })

  it("rejects 413 when Content-Length is absent on write (writes must declare size)", async () => {
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const cert = await mintDeviceCertForTest(alice, dev, nowSec - 10)
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    const c = fakeContext({
      method: "POST",
      url: "https://api/push/notes/abc",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": "x",
        "X-Starfish-Ts": String(Date.now()),
        "X-Starfish-Nonce": "n",
        // no Content-Length
      },
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 413 })
  })

  it("honours an explicit maxBodyBytes option", async () => {
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const cert = await mintDeviceCertForTest(alice, dev, nowSec - 10)
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
      maxBodyBytes: 16,
    })
    const c = fakeContext({
      method: "POST",
      url: "https://api/push/notes/abc",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": "x",
        "X-Starfish-Ts": String(Date.now()),
        "X-Starfish-Nonce": "n",
        "Content-Length": "32",
      },
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 413 })
  })

  // --- cap-cert verify ordering (cheap checks first) ---

  it("rejects with 'missing request signature headers' before cap-cert signature is verified", async () => {
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const cert = await mintDeviceCertForTest(alice, dev, nowSec - 10)
    // Tamper with cap-cert signature — if the resolver verified the cap
    // *before* checking sig headers, we'd see a "cap-cert bad-signature"
    // error. It must surface the cheap header check first.
    const tampered = { ...cert, sig: Buffer.from(new Uint8Array(64)).toString("base64") }
    const certB64 = Buffer.from(JSON.stringify(tampered)).toString("base64")

    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    const c = fakeContext({
      method: "GET",
      url: "https://api/foo",
      headers: { Authorization: `Cap ${certB64}` },
    })
    await expect(resolver(c)).rejects.toMatchObject({
      status: 401,
      message: expect.stringContaining("missing request signature headers"),
    })
  })

  // --- Authorization header length cap ---

  it("rejects 401 with error=cap-too-large when the cap header exceeds maxCapHeaderBytes", async () => {
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
      maxCapHeaderBytes: 8192,
    })
    // 10 KB of base64 padding after the "Cap " prefix
    const big = "A".repeat(10_000)
    const c = fakeContext({
      method: "GET",
      url: "https://api/x",
      headers: { Authorization: `Cap ${big}` },
    })
    await expect(resolver(c)).rejects.toMatchObject({
      status: 401,
      message: expect.stringContaining("cap-too-large"),
    })
  })

  it("accepts a cap header right at the 8 KB limit", async () => {
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const cert = await mintDeviceCertForTest(alice, dev, nowSec - 10)
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")
    // Sanity: the real cert is well under 8 KB
    expect(`Cap ${certB64}`.length).toBeLessThan(8192)

    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: "/pull/notes/abc",
      body: undefined,
      host: "api",
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/abc",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
      },
    })
    const auth = await resolver(c)
    expect(auth.identity).toBe(alice.userId)
  })

  it("throws 401 when the cap is in the revocation list", async () => {
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const cert = await mintDeviceCertForTest(alice, dev, nowSec - 10)
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")

    // Build a signed revocation list naming this cap
    const revStore = createInMemoryRevocationStore()
    const canonical = {
      v: 1 as const,
      iss: alice.edPubHex,
      issUserId: alice.userId,
      generation: 1,
      revoked: [{ sub: cert.sub, nonce: cert.nonce, exp: cert.exp }],
    }
    const { revocationListCanonicalSigningInput } = await import("@drakkar.software/starfish-protocol")
    const canonStr = revocationListCanonicalSigningInput(canonical)
    const sigBytes = ed25519.sign(new TextEncoder().encode(canonStr), alice.edPriv)
    const list = {
      ...canonical,
      sig: Buffer.from(sigBytes).toString("base64"),
    }
    const accept = revStore.acceptList(list)
    expect(accept.ok).toBe(true)

    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: "/pull/notes/x",
      body: undefined,
      host: "api",
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: revStore,
    })
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/x",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
      },
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 401 })
  })
})

// ── Parsing & input-validation hardening tests ───────────────────────────────
//
// The cap-resolver has a thick parsing surface (Authorization header, three
// X-Starfish-* headers, body buffering, JSON cap-cert, glob path matching).
// These tests pin down the error responses for each malformed-input class so
// regressions surface immediately.

describe("createCapCertRoleResolver — header parsing", () => {
  const baseResolver = () =>
    createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })

  it("rejects 401 when Authorization header is missing (allowAnonymous: false)", async () => {
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
      allowAnonymous: false,
    })
    const c = fakeContext({ method: "GET", url: "https://x/y" })
    await expect(resolver(c)).rejects.toMatchObject({ status: 401 })
  })

  it("returns anonymous public role when Authorization header is missing (allowAnonymous: true)", async () => {
    const c = fakeContext({ method: "GET", url: "https://x/y" })
    const auth = await baseResolver()(c)
    expect(auth.roles).toContain("public")
    expect(auth.identity).toBe("")
  })

  it("treats Authorization with an unknown scheme as anonymous (allowAnonymous: true)", async () => {
    // Current cap-resolver policy: only `Cap <...>` is recognized as a cap-cert
    // attempt. Any other scheme (Bearer, Basic, etc.) is indistinguishable from
    // "no auth header" for this resolver — callers wanting strict rejection
    // should set allowAnonymous: false (next test).
    const c = fakeContext({
      method: "GET",
      url: "https://x/y",
      headers: { Authorization: "Bearer notacap" },
    })
    const auth = await baseResolver()(c)
    expect(auth.roles).toContain("public")
  })

  it("rejects 401 when Authorization has an unknown scheme and allowAnonymous: false", async () => {
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
      allowAnonymous: false,
    })
    const c = fakeContext({
      method: "GET",
      url: "https://x/y",
      headers: { Authorization: "Bearer notacap" },
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 401 })
  })

  it("rejects 401 when Cap payload isn't valid base64", async () => {
    const c = fakeContext({
      method: "GET",
      url: "https://x/y",
      headers: { Authorization: "Cap !@#$%^&*()" },
    })
    await expect(baseResolver()(c)).rejects.toMatchObject({ status: 401 })
  })

  it("rejects 401 when Cap base64 decodes to non-JSON", async () => {
    const garbage = Buffer.from("not json at all").toString("base64")
    const c = fakeContext({
      method: "GET",
      url: "https://x/y",
      headers: { Authorization: `Cap ${garbage}` },
    })
    await expect(baseResolver()(c)).rejects.toMatchObject({ status: 401 })
  })

  it("rejects 401 when Cap JSON is missing required fields", async () => {
    const partial = Buffer.from(JSON.stringify({ v: 1 })).toString("base64")
    const c = fakeContext({
      method: "GET",
      url: "https://x/y",
      headers: { Authorization: `Cap ${partial}` },
    })
    await expect(baseResolver()(c)).rejects.toMatchObject({ status: 401 })
  })

  it("rejects 401 when Authorization header exceeds the 8 KB length cap", async () => {
    const oversize = "A".repeat(9_000)
    const c = fakeContext({
      method: "GET",
      url: "https://x/y",
      headers: { Authorization: `Cap ${oversize}` },
    })
    await expect(baseResolver()(c)).rejects.toMatchObject({ status: 401 })
  })

  it("accepts a normal-sized Authorization header (under 8 KB)", async () => {
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const cert = await mintDeviceCertForTest(alice, dev, nowSec - 10)
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")
    expect(certB64.length).toBeLessThan(8_192)

    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: "/pull/notes/abc",
      host: "api",
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/abc",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
      },
    })
    const auth = await baseResolver()(c)
    expect(auth.identity).toBe(alice.userId)
  })
})

describe("createCapCertRoleResolver — request-signature header parsing", () => {
  async function setupHeaders(): Promise<{ alice: RootKeys; dev: RootKeys; certB64: string }> {
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const cert = await mintDeviceCertForTest(alice, dev, nowSec - 10)
    return { alice, dev, certB64: Buffer.from(JSON.stringify(cert)).toString("base64") }
  }

  it("rejects 401 when X-Starfish-Sig is missing on a non-public request", async () => {
    const { certB64 } = await setupHeaders()
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/x",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Ts": String(Date.now()),
        "X-Starfish-Nonce": Buffer.from(new Uint8Array(16)).toString("base64"),
      },
    })
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 401 })
  })

  it("rejects 401 when X-Starfish-Ts is missing", async () => {
    const { dev, certB64 } = await setupHeaders()
    const req: SignableRequest = { method: "GET", pathAndQuery: "/pull/notes/x" }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/x",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Nonce": sig.nonce,
      },
    })
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 401 })
  })

  it("rejects 401 when X-Starfish-Nonce is missing", async () => {
    const { dev, certB64 } = await setupHeaders()
    const req: SignableRequest = { method: "GET", pathAndQuery: "/pull/notes/x" }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/x",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
      },
    })
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 401 })
  })

  it("rejects 401 when X-Starfish-Ts is non-numeric", async () => {
    const { dev, certB64 } = await setupHeaders()
    const req: SignableRequest = { method: "GET", pathAndQuery: "/pull/notes/x" }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/x",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": "not-a-number",
        "X-Starfish-Nonce": sig.nonce,
      },
    })
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 401 })
  })

  it("rejects 401 when X-Starfish-Ts is far outside the clock-skew window", async () => {
    const { dev, certB64 } = await setupHeaders()
    const req: SignableRequest = { method: "GET", pathAndQuery: "/pull/notes/x" }
    const sig = await signRequest(req, bytesToHex(dev.edPriv), {
      ts: Date.now() - 30 * 60 * 1000, // 30 minutes in the past
    })
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/x",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
      },
    })
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 401 })
  })

  it("rejects 401 when X-Starfish-Sig is malformed base64", async () => {
    const { dev, certB64 } = await setupHeaders()
    void dev
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/x",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": "!@#bad-base64",
        "X-Starfish-Ts": String(Date.now()),
        "X-Starfish-Nonce": Buffer.from(new Uint8Array(16)).toString("base64"),
      },
    })
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 401 })
  })

  it("is case-insensitive on header names", async () => {
    const { alice, dev, certB64 } = await setupHeaders()
    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: "/pull/notes/abc",
      host: "api",
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/abc",
      headers: {
        authorization: `Cap ${certB64}`, // lowercase
        "x-starfish-sig": sig.sig,
        "X-STARFISH-TS": String(sig.ts), // uppercase
        "X-Starfish-Nonce": sig.nonce, // mixed-case
      },
    })
    const auth = await createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })(c)
    expect(auth.identity).toBe(alice.userId)
  })
})

describe("createCapCertRoleResolver — body & Content-Length", () => {
  async function setup() {
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const cert = await mintDeviceCertForTest(alice, dev, nowSec - 10)
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")
    return { alice, dev, certB64 }
  }

  it("rejects 413 when a write request omits Content-Length", async () => {
    const { dev, certB64 } = await setup()
    const req: SignableRequest = {
      method: "POST",
      pathAndQuery: "/push/notes/abc",
      body: new TextEncoder().encode("{}"),
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const c = fakeContext({
      method: "POST",
      url: "https://api/push/notes/abc",
      body: new TextEncoder().encode("{}"),
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
        // no Content-Length
      },
    })
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 413 })
  })

  it("rejects 413 when Content-Length exceeds the cap", async () => {
    const { dev, certB64 } = await setup()
    const req: SignableRequest = {
      method: "POST",
      pathAndQuery: "/push/notes/abc",
      body: new TextEncoder().encode("{}"),
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const c = fakeContext({
      method: "POST",
      url: "https://api/push/notes/abc",
      body: new TextEncoder().encode("{}"),
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
        "Content-Length": "100000000",
      },
    })
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 413 })
  })

  it("rejects 413 when Content-Length is malformed", async () => {
    const { dev, certB64 } = await setup()
    const req: SignableRequest = {
      method: "POST",
      pathAndQuery: "/push/notes/abc",
      body: new TextEncoder().encode("{}"),
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const c = fakeContext({
      method: "POST",
      url: "https://api/push/notes/abc",
      body: new TextEncoder().encode("{}"),
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
        "Content-Length": "abc",
      },
    })
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 413 })
  })

  it("rejects 413 when Content-Length is negative", async () => {
    const { dev, certB64 } = await setup()
    const req: SignableRequest = {
      method: "POST",
      pathAndQuery: "/push/notes/abc",
      body: new TextEncoder().encode("{}"),
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const c = fakeContext({
      method: "POST",
      url: "https://api/push/notes/abc",
      body: new TextEncoder().encode("{}"),
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
        "Content-Length": "-5",
      },
    })
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 413 })
  })

  it("does NOT require Content-Length on GET (non-write methods)", async () => {
    const { alice, dev, certB64 } = await setup()
    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: "/pull/notes/abc",
      host: "api",
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/abc",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
      },
    })
    const auth = await createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })(c)
    expect(auth.identity).toBe(alice.userId)
  })

  it("accepts a write that advertises a within-budget Content-Length", async () => {
    const { alice, dev, certB64 } = await setup()
    const body = new TextEncoder().encode('{"hello":"world"}')
    const req: SignableRequest = {
      method: "POST",
      pathAndQuery: "/push/notes/abc",
      body,
      host: "api",
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const c = fakeContext({
      method: "POST",
      url: "https://api/push/notes/abc",
      body,
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
        "Content-Length": String(body.length),
      },
    })
    const auth = await createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })(c)
    expect(auth.identity).toBe(alice.userId)
  })

  it("parses Content-Length by the shared canonical rule (leading zeros accepted)", async () => {
    // `Content-Length` shares the `-?\d+` rule with `X-Starfish-Ts`, so the same
    // request can never authenticate with a size header one runtime reads differently.
    // Non-canonical-but-`int()`-parseable forms and JS `Number()`-only forms are 413;
    // leading zeros equal their base-10 value and are accepted (pinned for parity).
    const { alice, dev, certB64 } = await setup()
    const body = new TextEncoder().encode("{}")
    const req: SignableRequest = { method: "POST", pathAndQuery: "/push/notes/abc", body, host: "api" }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const ctx = (contentLength: string) =>
      fakeContext({
        method: "POST",
        url: "https://api/push/notes/abc",
        body,
        headers: {
          Authorization: `Cap ${certB64}`,
          "X-Starfish-Sig": sig.sig,
          "X-Starfish-Ts": String(sig.ts),
          "X-Starfish-Nonce": sig.nonce,
          "Content-Length": contentLength,
        },
      })
    const freshResolver = () =>
      createCapCertRoleResolver({
        nonceCache: createInMemoryNonceCache(),
        revocationStore: createInMemoryRevocationStore(),
      })
    for (const bad of ["+64", " 64", "64 ", "1_000", "0x10", "1e3", "12.5", ""]) {
      await expect(freshResolver()(ctx(bad))).rejects.toMatchObject({ status: 413 })
    }
    const auth = await freshResolver()(ctx("00000064"))
    expect(auth.identity).toBe(alice.userId)
  })
})

describe("createCapCertRoleResolver — scope.paths glob", () => {
  // Re-test matchScopePath behavior end-to-end via real cap-cert resolution.
  // Sanity-checks the `**` extension landed correctly and denylist precedence
  // holds in the request-path matcher.

  async function setupCertWithPaths(paths: string[]): Promise<{
    alice: RootKeys
    dev: RootKeys
    certB64: string
  }> {
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const unsigned: UnsignedCapCert = {
      v: 1,
      kind: "device",

      iss: alice.edPubHex,
      issUserId: alice.userId,
      sub: dev.edPubHex,
      subKem: dev.kemPubHex,
      scope: { ops: ["read", "list", "write"], collections: ["notes"], paths },
      nbf: nowSec - 10,
      exp: nowSec + 3600,
      nonce: Buffer.from(new Uint8Array(16).fill(7)).toString("base64"),
    }
    const cert = await signCapCert(unsigned, bytesToHex(alice.edPriv))
    return { alice, dev, certB64: Buffer.from(JSON.stringify(cert)).toString("base64") }
  }

  it("`*` glob matches within a single segment (no slash span)", async () => {
    const { dev, certB64 } = await setupCertWithPaths(["notes/*"])
    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: "/pull/notes/abc/deep",
      host: "api",
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/abc/deep",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
      },
    })
    await expect(
      createCapCertRoleResolver({
        nonceCache: createInMemoryNonceCache(),
        revocationStore: createInMemoryRevocationStore(),
      })(c),
    ).rejects.toMatchObject({ status: 403 })
  })

  it("`**` glob matches across slashes", async () => {
    const { alice, dev, certB64 } = await setupCertWithPaths(["notes/**"])
    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: "/pull/notes/abc/deep",
      host: "api",
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/abc/deep",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
      },
    })
    const auth = await createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })(c)
    expect(auth.identity).toBe(alice.userId)
  })

  it("`!`-prefix denylist beats wildcard allow", async () => {
    const { dev, certB64 } = await setupCertWithPaths(["notes/*", "!notes/_keyring"])
    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: "/pull/notes/_keyring",
      host: "api",
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/_keyring",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
      },
    })
    await expect(
      createCapCertRoleResolver({
        nonceCache: createInMemoryNonceCache(),
        revocationStore: createInMemoryRevocationStore(),
      })(c),
    ).rejects.toMatchObject({ status: 403 })
  })

  it("admin scope (no `!_keyring` deny) allows keyring writes", async () => {
    const { alice, dev, certB64 } = await setupCertWithPaths(["notes/*"])
    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: "/pull/notes/_keyring",
      host: "api",
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/_keyring",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
      },
    })
    const auth = await createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })(c)
    expect(auth.identity).toBe(alice.userId)
  })

  it("`paths` omitted → no path restriction (collections-only gate)", async () => {
    const alice = makeRoot(0x42)
    const dev = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const unsigned: UnsignedCapCert = {
      v: 1,
      kind: "device",

      iss: alice.edPubHex,
      issUserId: alice.userId,
      sub: dev.edPubHex,
      subKem: dev.kemPubHex,
      scope: { ops: ["read", "list", "write"], collections: ["notes"] },
      nbf: nowSec - 10,
      exp: nowSec + 3600,
      nonce: Buffer.from(new Uint8Array(16).fill(7)).toString("base64"),
    }
    const cert = await signCapCert(unsigned, bytesToHex(alice.edPriv))
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")

    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: "/pull/notes/anywhere/deep",
      host: "api",
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/anywhere/deep",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
      },
    })
    const auth = await createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })(c)
    expect(auth.identity).toBe(alice.userId)
  })

  it("a member cap with no scope.paths is rejected 403 at the resolver (defense-in-depth)", async () => {
    // The mint / server-side shape barrier already rejects a no-paths member
    // cap, but the resolver enforces it AGAIN as defense-in-depth (for a custom
    // plugin that skips the shape check, or future drift). Wire a permissive
    // plugin that registers `member` WITHOUT the barrier so the cap reaches the
    // resolver path gate, and assert the gate rejects it. A device cap with no
    // paths stays allowed (previous test) — only member/audience are gated.
    const alice = makeRoot(0x42)
    const bob = makeRoot(0x11)
    const nowSec = Math.floor(Date.now() / 1000)
    const unsigned: UnsignedCapCert = {
      v: 1,
      kind: "member",

      iss: alice.edPubHex,
      issUserId: alice.userId,
      sub: bob.edPubHex,
      subKem: bob.kemPubHex,
      subUserId: bob.userId,
      scope: { ops: ["read", "list", "write"], collections: ["notes"] }, // no `paths`
      nbf: nowSec - 10,
      exp: nowSec + 3600,
      nonce: Buffer.from(new Uint8Array(16).fill(9)).toString("base64"),
    }
    const cert = await signCapCert(unsigned, bytesToHex(alice.edPriv))
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")
    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: "/pull/notes/anything",
      host: "api",
    }
    const sig = await signRequest(req, bytesToHex(bob.edPriv))
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/anything",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
      },
    })
    const permissivePlugin = {
      name: "permissive-member",
      capValidators: { member: () => {} },
    }
    await expect(
      createCapCertRoleResolver({
        nonceCache: createInMemoryNonceCache(),
        revocationStore: createInMemoryRevocationStore(),
        plugins: [permissivePlugin],
      })(c),
    ).rejects.toThrow(/explicit scope\.paths/)
  })

  it("only deny entries → no allow ever matches → 403", async () => {
    const { dev, certB64 } = await setupCertWithPaths(["!notes/_keyring"])
    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: "/pull/notes/abc",
      host: "api",
    }
    const sig = await signRequest(req, bytesToHex(dev.edPriv))
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/abc",
      headers: {
        Authorization: `Cap ${certB64}`,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": String(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
      },
    })
    await expect(
      createCapCertRoleResolver({
        nonceCache: createInMemoryNonceCache(),
        revocationStore: createInMemoryRevocationStore(),
      })(c),
    ).rejects.toMatchObject({ status: 403 })
  })
})
