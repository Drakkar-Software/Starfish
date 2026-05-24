import { describe, it, expect, beforeAll } from "vitest"
import { ed25519 } from "@noble/curves/ed25519.js"
import { schnorr } from "@noble/curves/secp256k1.js"
import { sha256 } from "@noble/hashes/sha2.js"
import {
  configurePlatform,
  signRequest,
  buildRevocationList,
  userIdFromPubHex,
  type Alg,
  type CapCert,
  type SignableRequest,
} from "@drakkar.software/starfish-protocol"
import { webcrypto } from "node:crypto"
import { mintAudienceCap, mintMemberCap, scopes, sharingServerPlugin } from "@drakkar.software/starfish-sharing"
import { createCapCertRoleResolver } from "../../src/router/cap-resolver.js"
import { createInMemoryNonceCache } from "../../src/auth/nonce-cache.js"
import { createInMemoryRevocationStore } from "../../src/auth/revocation-store.js"

beforeAll(() => {
  configurePlatform({
    crypto: webcrypto as never,
    base64: {
      encode: (d: Uint8Array) => Buffer.from(d).toString("base64"),
      decode: (s: string) => new Uint8Array(Buffer.from(s, "base64")),
    },
  })
})

function hex(b: Uint8Array): string {
  let s = ""
  for (const x of b) s += x.toString(16).padStart(2, "0")
  return s
}

interface Key {
  edPrivHex: string
  edPubHex: string
  userId: string
}

function makeKey(seed: number): Key {
  const priv = new Uint8Array(32).fill(seed)
  const pub = ed25519.getPublicKey(priv)
  const edPubHex = hex(pub)
  return { edPrivHex: hex(priv), edPubHex, userId: hex(sha256(pub)).slice(0, 32) }
}

/** A secp256k1-schnorr presenter (x-only pubkey). Field names reuse `Key`. */
function makeSecpKey(seed: number): Key {
  const priv = new Uint8Array(32).fill(seed)
  const pub = schnorr.getPublicKey(priv) // 32-byte x-only
  const edPubHex = hex(pub)
  return { edPrivHex: hex(priv), edPubHex, userId: hex(sha256(pub)).slice(0, 32) }
}

const ISSUER = makeKey(0x42)

function fakeContext(opts: {
  method: string
  url: string
  headers?: Record<string, string>
  body?: Uint8Array
}): never {
  const headers = new Map<string, string>(
    Object.entries(opts.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
  )
  const bodyBytes = opts.body ?? new Uint8Array(0)
  return {
    req: {
      url: opts.url,
      method: opts.method,
      header(name?: string) {
        if (name === undefined) return Object.fromEntries(headers.entries())
        return headers.get(name.toLowerCase())
      },
      async arrayBuffer() {
        return bodyBytes.buffer.slice(
          bodyBytes.byteOffset,
          bodyBytes.byteOffset + bodyBytes.byteLength,
        )
      },
    },
  } as never
}

/** Build a GET-request header set signed by `presenter`, optionally with X-Starfish-Pub. */
async function redeemHeaders(
  cert: CapCert,
  presenter: Key,
  opts: {
    url: string
    includePub?: boolean
    nonce?: Uint8Array
    ts?: number
    /** Suite the presenter signs under (defaults to ed25519). */
    signAlg?: Alg
    /** Literal X-Starfish-Alg header value; omit to send no header. */
    algHeader?: string
  } = { url: "" },
): Promise<Record<string, string>> {
  const u = new URL(opts.url)
  const req: SignableRequest = {
    method: "GET",
    pathAndQuery: u.pathname + u.search,
    host: u.host,
  }
  const sig = await signRequest(req, presenter.edPrivHex, {
    nonce: opts.nonce,
    ts: opts.ts,
    alg: opts.signAlg,
  })
  const headers: Record<string, string> = {
    Authorization: `Cap ${Buffer.from(JSON.stringify(cert)).toString("base64")}`,
    "X-Starfish-Sig": sig.sig,
    "X-Starfish-Ts": String(sig.ts),
    "X-Starfish-Nonce": sig.nonce,
  }
  if (opts.includePub !== false) headers["X-Starfish-Pub"] = presenter.edPubHex
  if (opts.algHeader !== undefined) headers["X-Starfish-Alg"] = opts.algHeader
  return headers
}

function resolver(extra?: { revocationStore?: ReturnType<typeof createInMemoryRevocationStore> }) {
  return createCapCertRoleResolver({
    nonceCache: createInMemoryNonceCache(),
    revocationStore: extra?.revocationStore ?? createInMemoryRevocationStore(),
    plugins: [sharingServerPlugin],
  })
}

const URL_OK = "https://api.example.com/pull/broadcast/post-1"
const nowSec = () => Math.floor(Date.now() / 1000)

async function openCap(): Promise<CapCert> {
  return mintAudienceCap(ISSUER.edPrivHex, ISSUER.edPubHex, "broadcast", scopes.readOnly("broadcast"), {
    nbf: nowSec() - 10,
    ttlSec: 3600,
  })
}

describe("audience cap resolver", () => {
  it("open cap (no aud): any identity authorized; identity == sha256(presenterPub)", async () => {
    const cert = await openCap()
    const anyone = makeKey(0x71)
    const auth = await resolver()(
      fakeContext({ method: "GET", url: URL_OK, headers: await redeemHeaders(cert, anyone, { url: URL_OK }) }),
    )
    expect(auth.identity).toBe(userIdFromPubHex(anyone.edPubHex))
    expect(auth.roles).toContain("cap:read:broadcast")
    expect(auth.roles).toContain(`delegated:${ISSUER.userId}:broadcast`)
  })

  it("restricted cap: a listed identity is authorized", async () => {
    const bob = makeKey(0x55)
    const cert = await mintAudienceCap(
      ISSUER.edPrivHex,
      ISSUER.edPubHex,
      "broadcast",
      scopes.readOnly("broadcast"),
      { audience: [bob.edPubHex], nbf: nowSec() - 10, ttlSec: 3600 },
    )
    const auth = await resolver()(
      fakeContext({ method: "GET", url: URL_OK, headers: await redeemHeaders(cert, bob, { url: URL_OK }) }),
    )
    expect(auth.identity).toBe(bob.userId)
  })

  it("restricted cap: a secp256k1 presenter is rejected 401 (allow-list is ed25519-only)", async () => {
    // The allow-list stores bare 32-byte hex with no suite tag. A secp256k1
    // x-only presenter must NOT be admitted by a raw-hex match against an
    // Ed25519 allow-list — the resolver pins allow-listed audiences to ed25519.
    const presenter = makeSecpKey(0x71)
    const cert = await mintAudienceCap(
      ISSUER.edPrivHex,
      ISSUER.edPubHex,
      "broadcast",
      scopes.readOnly("broadcast"),
      // Even with the presenter's own hex listed, the suite mismatch is rejected.
      { audience: [presenter.edPubHex], nbf: nowSec() - 10, ttlSec: 3600 },
    )
    await expect(
      resolver()(
        fakeContext({
          method: "GET",
          url: URL_OK,
          headers: await redeemHeaders(cert, presenter, {
            url: URL_OK,
            signAlg: "secp256k1-schnorr",
            algHeader: "secp256k1-schnorr",
          }),
        }),
      ),
    ).rejects.toMatchObject({ status: 401 })
  })

  it("restricted cap: a non-listed identity is rejected 403", async () => {
    const bob = makeKey(0x55)
    const mallory = makeKey(0x66)
    const cert = await mintAudienceCap(
      ISSUER.edPrivHex,
      ISSUER.edPubHex,
      "broadcast",
      scopes.readOnly("broadcast"),
      { audience: [bob.edPubHex], nbf: nowSec() - 10, ttlSec: 3600 },
    )
    await expect(
      resolver()(
        fakeContext({ method: "GET", url: URL_OK, headers: await redeemHeaders(cert, mallory, { url: URL_OK }) }),
      ),
    ).rejects.toMatchObject({ status: 403 })
  })

  it("missing X-Starfish-Pub on an audience cap is rejected 401", async () => {
    const cert = await openCap()
    const anyone = makeKey(0x71)
    await expect(
      resolver()(
        fakeContext({
          method: "GET",
          url: URL_OK,
          headers: await redeemHeaders(cert, anyone, { url: URL_OK, includePub: false }),
        }),
      ),
    ).rejects.toMatchObject({ status: 401 })
  })

  it("malformed X-Starfish-Pub is rejected 401", async () => {
    const cert = await openCap()
    const anyone = makeKey(0x71)
    const headers = await redeemHeaders(cert, anyone, { url: URL_OK })
    headers["X-Starfish-Pub"] = "NOT-HEX"
    await expect(
      resolver()(fakeContext({ method: "GET", url: URL_OK, headers })),
    ).rejects.toMatchObject({ status: 401 })
  })

  it("a malformed X-Starfish-Alg on an audience cap is rejected 401 (fail-closed)", async () => {
    const cert = await openCap()
    const anyone = makeKey(0x71)
    // Signs ed25519 but declares an unknown suite — the resolver must reject the
    // header before dispatching to any suite, not fall back silently.
    const headers = await redeemHeaders(cert, anyone, { url: URL_OK, algHeader: "rsa" })
    await expect(
      resolver()(fakeContext({ method: "GET", url: URL_OK, headers })),
    ).rejects.toMatchObject({ status: 401 })
  })

  it("an explicit X-Starfish-Alg: ed25519 on an audience cap is accepted", async () => {
    const cert = await openCap()
    const anyone = makeKey(0x71)
    const headers = await redeemHeaders(cert, anyone, { url: URL_OK, algHeader: "ed25519" })
    const auth = await resolver()(fakeContext({ method: "GET", url: URL_OK, headers }))
    expect(auth.identity).toBe(userIdFromPubHex(anyone.edPubHex))
  })

  it("a secp256k1-schnorr presenter redeems an audience cap (cross-suite, header-driven)", async () => {
    // The presenter's suite is unrelated to the cap's issAlg; it arrives only in
    // X-Starfish-Alg and the resolver must verify the request signature under it.
    const cert = await openCap()
    const presenter = makeSecpKey(0x71)
    const headers = await redeemHeaders(cert, presenter, {
      url: URL_OK,
      signAlg: "secp256k1-schnorr",
      algHeader: "secp256k1-schnorr",
    })
    const auth = await resolver()(fakeContext({ method: "GET", url: URL_OK, headers }))
    expect(auth.identity).toBe(userIdFromPubHex(presenter.edPubHex))
  })

  it("a secp256k1 presenter whose X-Starfish-Alg lies (claims ed25519) fails 401", async () => {
    // Signature bytes are secp256k1 but the header says ed25519 → verify under the
    // wrong suite must fail closed, never authorize.
    const cert = await openCap()
    const presenter = makeSecpKey(0x71)
    const headers = await redeemHeaders(cert, presenter, {
      url: URL_OK,
      signAlg: "secp256k1-schnorr",
      algHeader: "ed25519",
    })
    await expect(
      resolver()(fakeContext({ method: "GET", url: URL_OK, headers })),
    ).rejects.toMatchObject({ status: 401 })
  })

  it("two different presenters reusing the same nonce both succeed (nonce-cache keyed by presenter)", async () => {
    const cert = await openCap()
    const a = makeKey(0x71)
    const b = makeKey(0x72)
    const r = resolver()
    const sharedNonce = new Uint8Array(16).fill(0x5a)
    const authA = await r(
      fakeContext({ method: "GET", url: URL_OK, headers: await redeemHeaders(cert, a, { url: URL_OK, nonce: sharedNonce }) }),
    )
    const authB = await r(
      fakeContext({ method: "GET", url: URL_OK, headers: await redeemHeaders(cert, b, { url: URL_OK, nonce: sharedNonce }) }),
    )
    expect(authA.identity).toBe(userIdFromPubHex(a.edPubHex))
    expect(authB.identity).toBe(userIdFromPubHex(b.edPubHex))
  })

  it("same presenter replaying the same nonce is rejected 401", async () => {
    const cert = await openCap()
    const a = makeKey(0x71)
    const r = resolver()
    const nonce = new Uint8Array(16).fill(0x33)
    const ts = Date.now()
    await r(fakeContext({ method: "GET", url: URL_OK, headers: await redeemHeaders(cert, a, { url: URL_OK, nonce, ts }) }))
    await expect(
      r(fakeContext({ method: "GET", url: URL_OK, headers: await redeemHeaders(cert, a, { url: URL_OK, nonce, ts }) })),
    ).rejects.toMatchObject({ status: 401 })
  })

  it("an audience cap revoked by nonce (sub:'') is rejected 401", async () => {
    const cert = await openCap()
    const anyone = makeKey(0x71)
    const store = createInMemoryRevocationStore()
    const list = buildRevocationList({
      issEdPubHex: ISSUER.edPubHex,
      issEdPrivHex: ISSUER.edPrivHex,
      generation: 1,
      revoked: [{ sub: "", nonce: cert.nonce, exp: cert.exp }],
    })
    expect(store.acceptList(list).ok).toBe(true)
    await expect(
      resolver({ revocationStore: store })(
        fakeContext({ method: "GET", url: URL_OK, headers: await redeemHeaders(cert, anyone, { url: URL_OK }) }),
      ),
    ).rejects.toMatchObject({ status: 401 })
  })

  it("a subject-wide revocation of sub:'' does NOT blanket-revoke audience caps", async () => {
    // Footgun guard: an empty subject in `revokedSubjects` must not match the
    // subject-wide set, or every audience cap from the issuer would be revoked.
    const cert = await openCap()
    const anyone = makeKey(0x71)
    const store = createInMemoryRevocationStore()
    const list = buildRevocationList({
      issEdPubHex: ISSUER.edPubHex,
      issEdPrivHex: ISSUER.edPrivHex,
      generation: 1,
      revoked: [],
      revokedSubjects: [{ sub: "", exp: cert.exp }],
    })
    expect(store.acceptList(list).ok).toBe(true)
    const auth = await resolver({ revocationStore: store })(
      fakeContext({ method: "GET", url: URL_OK, headers: await redeemHeaders(cert, anyone, { url: URL_OK }) }),
    )
    expect(auth.identity).toBe(userIdFromPubHex(anyone.edPubHex))
  })

  it("an audience cap is rejected 401 when the sharing plugin is not wired (strict-kind dispatch)", async () => {
    const cert = await openCap()
    const anyone = makeKey(0x71)
    const r = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
      // no plugins → default device-only plugin → audience kind has no validator
    })
    await expect(
      r(fakeContext({ method: "GET", url: URL_OK, headers: await redeemHeaders(cert, anyone, { url: URL_OK }) })),
    ).rejects.toMatchObject({ status: 401 })
  })

  it("a writer audience cap authorizes a JSON POST signed over the body", async () => {
    const writer = makeKey(0x71)
    const cert = await mintAudienceCap(
      ISSUER.edPrivHex,
      ISSUER.edPubHex,
      "broadcast",
      scopes.writer("broadcast"),
      { audience: [writer.edPubHex], nbf: nowSec() - 10, ttlSec: 3600 },
    )
    const url = "https://api.example.com/push/broadcast/post-1"
    const body = new TextEncoder().encode(JSON.stringify({ hello: "world" }))
    const u = new URL(url)
    const req: SignableRequest = {
      method: "POST",
      pathAndQuery: u.pathname + u.search,
      body,
      host: u.host,
    }
    const sig = await signRequest(req, writer.edPrivHex)
    const headers: Record<string, string> = {
      Authorization: `Cap ${Buffer.from(JSON.stringify(cert)).toString("base64")}`,
      "X-Starfish-Sig": sig.sig,
      "X-Starfish-Ts": String(sig.ts),
      "X-Starfish-Nonce": sig.nonce,
      "X-Starfish-Pub": writer.edPubHex,
      "Content-Type": "application/json",
      "Content-Length": String(body.length),
    }
    const auth = await resolver()(fakeContext({ method: "POST", url, body, headers }))
    expect(auth.identity).toBe(userIdFromPubHex(writer.edPubHex))
    expect(auth.roles).toContain("cap:write:broadcast")
  })

  it("a member cap still authorizes when X-Starfish-Pub is present (forward-compat, header ignored)", async () => {
    const bob = makeKey(0x55)
    const cert = await mintMemberCap(
      ISSUER.edPrivHex,
      ISSUER.edPubHex,
      { edPubHex: bob.edPubHex, kemPubHex: "ee".repeat(32), userIdHex: bob.userId },
      "broadcast",
      scopes.readOnly("broadcast"),
      { nbf: nowSec() - 10, ttlSec: 3600 },
    )
    // Member caps verify against cert.sub; the bogus X-Starfish-Pub must be ignored.
    const headers = await redeemHeaders(cert, bob, { url: URL_OK })
    headers["X-Starfish-Pub"] = "cc".repeat(32)
    const auth = await resolver()(fakeContext({ method: "GET", url: URL_OK, headers }))
    expect(auth.identity).toBe(bob.userId)
  })

  it("an expired audience cap is rejected 401", async () => {
    const cert = await mintAudienceCap(
      ISSUER.edPrivHex,
      ISSUER.edPubHex,
      "broadcast",
      scopes.readOnly("broadcast"),
      { nbf: nowSec() - 4000, ttlSec: 1000 }, // exp ~3000s in the past, beyond 300s skew
    )
    const anyone = makeKey(0x71)
    await expect(
      resolver()(
        fakeContext({ method: "GET", url: URL_OK, headers: await redeemHeaders(cert, anyone, { url: URL_OK }) }),
      ),
    ).rejects.toMatchObject({ status: 401 })
  })
})
