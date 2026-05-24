/**
 * Plugin-host behavior of the cap-cert role resolver.
 *
 * When `plugins` is omitted, behavior is unchanged. When `plugins` is
 * provided, the resolver dispatches per-kind validators after the core
 * `verifyCapCert` checks. Strict-kind dispatch rejects unknown kinds;
 * non-strict falls through.
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
  type SignableRequest,
  type UnsignedCapCert,
} from "@drakkar.software/starfish-protocol"
import {
  createCapCertRoleResolver,
  defaultServerPlugin,
  type ServerPlugin,
} from "../../src/index.js"
import { createInMemoryNonceCache } from "../../src/auth/nonce-cache.js"
import { createInMemoryRevocationStore } from "../../src/auth/revocation-store.js"

beforeAll(() => {
  configurePlatform({
    crypto: webcrypto as unknown as Crypto,
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
  edPrivHex: string
  edPubHex: string
  kemPubHex: string
  userId: string
}

function makeRoot(seed: number): RootKeys {
  const edPriv = new Uint8Array(32).fill(seed)
  const edPub = ed25519.getPublicKey(edPriv)
  const kemPriv = new Uint8Array(32).fill(seed + 1)
  const kemPub = x25519.getPublicKey(kemPriv)
  return {
    edPrivHex: bytesToHex(edPriv),
    edPubHex: bytesToHex(edPub),
    kemPubHex: bytesToHex(kemPub),
    userId: bytesToHex(sha256(edPub)).slice(0, 32),
  }
}

async function buildSignedDeviceCap(iss: RootKeys, sub: RootKeys): Promise<CapCert> {
  const nbf = Math.floor(Date.now() / 1000) - 10
  const unsigned: UnsignedCapCert = {
    v: 1,
    kind: "device",
    issAlg: "ed25519",
    iss: iss.edPubHex,
    issUserId: iss.userId,
    sub: sub.edPubHex,
    subKem: sub.kemPubHex,
    scope: { ops: ["read", "list"], collections: ["*"], paths: ["**"] },
    nbf,
    exp: nbf + 3600,
    nonce: Buffer.from(new Uint8Array(16).fill(0xa1)).toString("base64"),
  }
  return await signCapCert(unsigned, iss.edPrivHex)
}

async function buildSignedMemberCap(iss: RootKeys, sub: RootKeys): Promise<CapCert> {
  const nbf = Math.floor(Date.now() / 1000) - 10
  const unsigned: UnsignedCapCert = {
    v: 1,
    kind: "member",
    issAlg: "ed25519",
    iss: iss.edPubHex,
    issUserId: iss.userId,
    sub: sub.edPubHex,
    subKem: sub.kemPubHex,
    subUserId: sub.userId,
    scope: { ops: ["read", "list"], collections: ["shared"], paths: ["shared/**", "!shared/_members"] },
    nbf,
    exp: nbf + 3600,
    nonce: Buffer.from(new Uint8Array(16).fill(0xb2)).toString("base64"),
  }
  return await signCapCert(unsigned, iss.edPrivHex)
}

function fakeContext(opts: {
  method: string
  url: string
  headers: Record<string, string>
}): any {
  const headers = new Map<string, string>(
    Object.entries(opts.headers).map(([k, v]) => [k.toLowerCase(), v]),
  )
  return {
    req: {
      url: opts.url,
      method: opts.method,
      header(name?: string) {
        if (name === undefined) return Object.fromEntries(headers.entries())
        return headers.get(name.toLowerCase())
      },
      param() {
        return undefined
      },
      async arrayBuffer() {
        return new ArrayBuffer(0)
      },
      async text() {
        return ""
      },
    },
  }
}

async function buildRequestContext(cert: CapCert, sub: RootKeys) {
  // Bind the signature to the same host the resolver reconstructs from the
  // request URL (`new URL("https://api/...").host === "api"`).
  const req: SignableRequest = {
    method: "GET",
    pathAndQuery: "/pull/notes/abc",
    body: undefined,
    host: "api",
  }
  const sig = await signRequest(req, sub.edPrivHex)
  return fakeContext({
    method: "GET",
    url: "https://api/pull/notes/abc",
    headers: {
      Authorization: `Cap ${Buffer.from(JSON.stringify(cert)).toString("base64")}`,
      "X-Starfish-Sig": sig.sig,
      "X-Starfish-Ts": String(sig.ts),
      "X-Starfish-Nonce": sig.nonce,
    },
  })
}

describe("createCapCertRoleResolver — no plugins (legacy path)", () => {
  it("accepts a valid device cap unchanged", async () => {
    const alice = makeRoot(0x11)
    const cert = await buildSignedDeviceCap(alice, alice)
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
    })
    const ctx = await buildRequestContext(cert, alice)
    const result = await resolver(ctx)
    expect(result.identity).toBe(alice.userId)
  })
})

describe("createCapCertRoleResolver — plugin dispatch", () => {
  it("with [defaultServerPlugin]: device cap accepted (recognized kind)", async () => {
    const alice = makeRoot(0x12)
    const cert = await buildSignedDeviceCap(alice, alice)
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
      plugins: [defaultServerPlugin],
    })
    const ctx = await buildRequestContext(cert, alice)
    const result = await resolver(ctx)
    expect(result.identity).toBe(alice.userId)
  })

  it("with [defaultServerPlugin]: member cap rejected (device-only default)", async () => {
    const alice = makeRoot(0x21)
    const bob = makeRoot(0x22)
    const cert = await buildSignedMemberCap(alice, bob)
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
      plugins: [defaultServerPlugin],
    })
    const ctx = await buildRequestContext(cert, bob)
    await expect(resolver(ctx)).rejects.toMatchObject({ status: 401 })
  })

  it("strictKindDispatch (default): unregistered kind rejects 401", async () => {
    const alice = makeRoot(0x13)
    const cert = await buildSignedDeviceCap(alice, alice)
    // Plugin set covers only `member`; the device cap should be rejected.
    const memberOnly: ServerPlugin = {
      name: "member-only",
      capValidators: { member: () => {} },
    }
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
      plugins: [memberOnly],
    })
    const ctx = await buildRequestContext(cert, alice)
    await expect(resolver(ctx)).rejects.toMatchObject({ status: 401 })
  })

  it("strictKindDispatch=false: unregistered kind falls through", async () => {
    const alice = makeRoot(0x14)
    const cert = await buildSignedDeviceCap(alice, alice)
    const memberOnly: ServerPlugin = {
      name: "member-only",
      capValidators: { member: () => {} },
    }
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
      plugins: [memberOnly],
      strictKindDispatch: false,
    })
    const ctx = await buildRequestContext(cert, alice)
    const result = await resolver(ctx)
    expect(result.identity).toBe(alice.userId)
  })

  it("validator that throws rejects 401 with the thrown message", async () => {
    const alice = makeRoot(0x15)
    const cert = await buildSignedDeviceCap(alice, alice)
    const failing: ServerPlugin = {
      name: "failing",
      capValidators: {
        device: () => {
          throw new Error("custom-policy-violation")
        },
      },
    }
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
      plugins: [failing],
    })
    const ctx = await buildRequestContext(cert, alice)
    await expect(resolver(ctx)).rejects.toMatchObject({
      status: 401,
      message: expect.stringContaining("custom-policy-violation"),
    })
  })

  it("multiple plugins composing the same kind: validators run in order, first throw rejects", async () => {
    const alice = makeRoot(0x16)
    const cert = await buildSignedDeviceCap(alice, alice)
    const calls: string[] = []
    const ok: ServerPlugin = {
      name: "ok",
      capValidators: {
        device: () => {
          calls.push("ok")
        },
      },
    }
    const fail: ServerPlugin = {
      name: "fail",
      capValidators: {
        device: () => {
          calls.push("fail")
          throw new Error("policy-X")
        },
      },
    }
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
      plugins: [ok, fail],
    })
    const ctx = await buildRequestContext(cert, alice)
    await expect(resolver(ctx)).rejects.toMatchObject({ status: 401 })
    expect(calls).toEqual(["ok", "fail"])
  })

  it("anonymous request still short-circuits to public regardless of plugins", async () => {
    const resolver = createCapCertRoleResolver({
      nonceCache: createInMemoryNonceCache(),
      revocationStore: createInMemoryRevocationStore(),
      plugins: [defaultServerPlugin],
      allowAnonymous: true,
    })
    const ctx = fakeContext({
      method: "GET",
      url: "https://api/pull/notes/abc",
      headers: {},
    })
    const result = await resolver(ctx)
    expect(result.identity).toBe("")
    expect(result.roles).toContain("public")
  })
})
