/**
 * Member-cap structural bounds — both the well-formedness assertion (used
 * by `mintMemberCap`) and the server verifier must catch forbidden
 * member-cap shapes:
 *
 * - Path that lands in the issuer's `users/<issUserId>/` namespace.
 * - Wildcard collection (`"*"`).
 * - `subUserId === issUserId` (a member cap to oneself).
 *
 * The server-side cap-resolver must reject forged member caps that bypass
 * the client-side guardrails.
 */

import { describe, it, expect, beforeAll } from "vitest"
import { webcrypto } from "node:crypto"
import { ed25519, x25519 } from "@noble/curves/ed25519.js"
import { sha256 } from "@noble/hashes/sha2.js"
import {
  configurePlatform,
  signCapCert,
  signRequest,
  type CapCert,
  type UnsignedCapCert,
  type SignableRequest,
} from "@drakkar.software/starfish-protocol"
import { assertMemberCapShape, sharingServerPlugin, scopes } from "@drakkar.software/starfish-sharing"
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
  edPubHex: string
  edPrivHex: string
  kemPubHex: string
  userId: string
}

function makeRoot(seed: number): RootKeys {
  const edPriv = new Uint8Array(32).fill(seed)
  const edPub = ed25519.getPublicKey(edPriv)
  const userId = bytesToHex(sha256(edPub)).slice(0, 32)
  const kemPriv = new Uint8Array(32).fill(seed + 1)
  const kemPub = x25519.getPublicKey(kemPriv)
  return {
    edPriv,
    edPubHex: bytesToHex(edPub),
    edPrivHex: bytesToHex(edPriv),
    kemPubHex: bytesToHex(kemPub),
    userId,
  }
}

function buildUnsignedMember(
  iss: RootKeys,
  sub: RootKeys,
  scope: UnsignedCapCert["scope"],
  nonceSeed = 0x07,
): UnsignedCapCert {
  const nbf = Math.floor(Date.now() / 1000) - 10
  return {
    v: 1,
    kind: "member",
    iss: iss.edPubHex,
    issUserId: iss.userId,
    sub: sub.edPubHex,
    subKem: sub.kemPubHex,
    subUserId: sub.userId,
    scope,
    nbf,
    exp: nbf + 3600,
    nonce: Buffer.from(new Uint8Array(16).fill(nonceSeed)).toString("base64"),
  }
}

function fakeContext(opts: {
  method: string
  url: string
  headers?: Record<string, string>
  body?: Uint8Array
  params?: Record<string, string>
}): any {
  const headers = new Map<string, string>(
    Object.entries(opts.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
  )
  const bodyBytes = opts.body ?? new Uint8Array(0)
  const params = opts.params ?? {}
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
      param(key?: string): any {
        if (key === undefined) return { ...params }
        return params[key]
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

describe("member-cap client-side mint guardrails (assertMemberCapShape)", () => {
  it("throws 'member-private-path' when path lands in issuer namespace", async () => {
    const alice = makeRoot(0x61)
    const bob = makeRoot(0x62)
    const unsigned = buildUnsignedMember(alice, bob, {
      ops: ["read", "write"],
      collections: ["users"],
      paths: ["users/{identity}/private"],
    })
    expect(() => assertMemberCapShape(unsigned)).toThrowError(
      expect.objectContaining({ code: "member-private-path" }),
    )
  })

  it("throws 'member-wildcard-collections' on '*' in collections", async () => {
    const alice = makeRoot(0x63)
    const bob = makeRoot(0x64)
    const unsigned = buildUnsignedMember(alice, bob, {
      ops: ["read"],
      collections: ["*"],
    })
    expect(() => assertMemberCapShape(unsigned)).toThrowError(
      expect.objectContaining({ code: "member-wildcard-collections" }),
    )
  })

  it("throws 'member-self' when subUserId === issUserId", async () => {
    const alice = makeRoot(0x65)
    // Same seed: same user.
    const aliceClone = makeRoot(0x65)
    expect(aliceClone.userId).toBe(alice.userId)
    const unsigned = buildUnsignedMember(alice, aliceClone, {
      ops: ["read"],
      collections: ["shared"],
    })
    expect(() => assertMemberCapShape(unsigned)).toThrowError(
      expect.objectContaining({ code: "member-self" }),
    )
  })
})

describe("member-cap structural barrier (assertMemberCapShape, owned by starfish-sharing)", () => {
  it("forged member cap with private-namespace path: assertMemberCapShape throws 'member-private-path'", async () => {
    const alice = makeRoot(0x71)
    const bob = makeRoot(0x72)
    const unsigned = buildUnsignedMember(alice, bob, {
      ops: ["read"],
      collections: ["users"],
      paths: ["users/{identity}/private"],
    }, 0x71)
    // signCapCert does NOT validate shape, so this bypasses the client
    // guardrail; the sharing plugin re-runs assertMemberCapShape server-side.
    const cert: CapCert = await signCapCert(unsigned, alice.edPrivHex)
    expect(() => assertMemberCapShape(cert)).toThrowError(
      expect.objectContaining({ code: "member-private-path" }),
    )
  })

  it("forged member cap with wildcard collections: assertMemberCapShape throws 'member-wildcard-collections'", async () => {
    const alice = makeRoot(0x73)
    const bob = makeRoot(0x74)
    const unsigned = buildUnsignedMember(alice, bob, {
      ops: ["read"],
      collections: ["*"],
    }, 0x72)
    const cert: CapCert = await signCapCert(unsigned, alice.edPrivHex)
    expect(() => assertMemberCapShape(cert)).toThrowError(
      expect.objectContaining({ code: "member-wildcard-collections" }),
    )
  })

  it("forged member-self cap: assertMemberCapShape throws 'member-self'", async () => {
    const alice = makeRoot(0x75)
    const unsigned = buildUnsignedMember(alice, alice, {
      ops: ["read"],
      collections: ["shared"],
    }, 0x73)
    const cert: CapCert = await signCapCert(unsigned, alice.edPrivHex)
    expect(() => assertMemberCapShape(cert)).toThrowError(
      expect.objectContaining({ code: "member-self" }),
    )
  })

  it("resolver rejects a forged bad-shape member cap presented via Authorization header", async () => {
    const alice = makeRoot(0x81)
    const bob = makeRoot(0x82)
    const unsigned = buildUnsignedMember(alice, bob, {
      ops: ["read"],
      collections: ["*"],
    }, 0x81)
    const cert: CapCert = await signCapCert(unsigned, alice.edPrivHex)
    const certB64 = Buffer.from(JSON.stringify(cert)).toString("base64")

    // Sign with the SAME host the server extracts from the URL ("api"), so the
    // request signature is VALID and the rejection can only come from the
    // resolver's cap-cert handling — not an incidental host/sig mismatch.
    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: "/pull/shared/abc",
      body: undefined,
      host: "api",
    }
    const sig = await signRequest(req, bob.edPrivHex)
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/shared/abc",
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

/**
 * The cap-resolver must be SECURE BY DEFAULT.
 *
 * The member-cap structural barriers live in `assertMemberCapShape`
 * (starfish-sharing), wired via `sharingServerPlugin`. A resolver built WITHOUT
 * `plugins` must still reject member caps (strict-kind dispatch is always on),
 * so a forged member cap cannot sail through with baseline checks only. These
 * tests sign the request with the correct host so the request signature is
 * valid — the resolver itself must do the rejecting.
 */
describe("cap-resolver secure-by-default (member kind requires a validator)", () => {
  /** Build a valid signature for the given cap subject + host "api". */
  async function signedHeadersFor(
    cert: CapCert,
    pathAndQuery: string,
    subEdPrivHex: string,
  ): Promise<Record<string, string>> {
    const req: SignableRequest = { method: "GET", pathAndQuery, body: undefined, host: "api" }
    const sig = await signRequest(req, subEdPrivHex)
    return {
      Authorization: `Cap ${Buffer.from(JSON.stringify(cert)).toString("base64")}`,
      "X-Starfish-Sig": sig.sig,
      "X-Starfish-Ts": String(sig.ts),
      "X-Starfish-Nonce": sig.nonce,
    }
  }

  it("forged wildcard member cap is REJECTED by a no-plugins resolver", async () => {
    const alice = makeRoot(0x91)
    const bob = makeRoot(0x92)
    const unsigned = buildUnsignedMember(alice, bob, {
      ops: ["read", "write"],
      collections: ["*"],
      paths: ["**"],
    }, 0x91)
    const cert = await signCapCert(unsigned, alice.edPrivHex)
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
      // No `plugins` → device-only by default; `member` has no validator.
    })
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/anything/x",
      headers: await signedHeadersFor(cert, "/pull/anything/x", bob.edPrivHex),
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 401 })
  })

  it("forged member cap that reaches <col>/_keyring write is REJECTED with sharingServerPlugin", async () => {
    const alice = makeRoot(0x93)
    const bob = makeRoot(0x94)
    // ops include write, paths reach notes/_keyring with NO `!notes/_keyring` deny.
    const unsigned = buildUnsignedMember(alice, bob, {
      ops: ["read", "write"],
      collections: ["notes"],
      paths: ["notes/**"],
    }, 0x93)
    const cert = await signCapCert(unsigned, alice.edPrivHex)
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
      plugins: [sharingServerPlugin],
    })
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/x",
      headers: await signedHeadersFor(cert, "/pull/notes/x", bob.edPrivHex),
    })
    await expect(resolver(c)).rejects.toMatchObject({ status: 401 })
  })

  it("a well-formed member cap STILL resolves with sharingServerPlugin (no over-rejection)", async () => {
    const alice = makeRoot(0x95)
    const bob = makeRoot(0x96)
    const unsigned = buildUnsignedMember(alice, bob, scopes.readOnly("shared"), 0x95)
    const cert = await signCapCert(unsigned, alice.edPrivHex)
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
      plugins: [sharingServerPlugin],
    })
    const c = fakeContext({
      method: "GET",
      url: "https://api/pull/shared/abc",
      headers: await signedHeadersFor(cert, "/pull/shared/abc", bob.edPrivHex),
    })
    const auth = await resolver(c)
    expect(auth.identity).toBe(bob.userId)
    expect(auth.roles).toContain(`delegated:${alice.userId}:shared`)
  })
})
