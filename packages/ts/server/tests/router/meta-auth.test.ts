/**
 * `authenticateMetaRequest`: the bodyless meta-request authenticator. Accepts
 * device & member caps; rejects audience, bad signature, expired cap, replayed
 * nonce, revoked cap, and a forged member shape.
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
import { sharingServerPlugin } from "@drakkar.software/starfish-sharing"
import { identitiesServerPlugin } from "@drakkar.software/starfish-identities"
import { authenticateMetaRequest } from "../../src/router/cap-resolver.js"
import { composePluginValidators } from "../../src/plugins.js"
import { createInMemoryNonceCache } from "../../src/auth/nonce-cache.js"
import { createInMemoryRevocationStore } from "../../src/auth/revocation-store.js"
import type { NonceCache } from "../../src/auth/nonce-cache.js"
import type { RevocationStore } from "../../src/auth/revocation-store.js"

beforeAll(() => {
  configurePlatform({
    crypto: webcrypto as any,
    base64: {
      encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
      decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
    },
  })
})

const HOST = "test"
const PATH = "/v1/events?ids=p1"
const PLUGIN_VALIDATORS = composePluginValidators([identitiesServerPlugin, sharingServerPlugin])

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
  const userId = bytesToHex(sha256(edPub)).slice(0, 32)
  const kemPriv = new Uint8Array(32).fill(seed + 1)
  const kemPub = x25519.getPublicKey(kemPriv)
  return { edPrivHex: bytesToHex(edPriv), edPubHex: bytesToHex(edPub), kemPubHex: bytesToHex(kemPub), userId }
}

async function mintDevice(iss: RootKeys, sub: RootKeys, nbf: number, ttl = 3600): Promise<CapCert> {
  const unsigned: UnsignedCapCert = {
    v: 1,
    kind: "device",
    iss: iss.edPubHex,
    issUserId: iss.userId,
    sub: sub.edPubHex,
    subKem: sub.kemPubHex,
    scope: { ops: ["read", "list", "write"], collections: ["notes"], paths: ["notes/*"] },
    nbf,
    exp: nbf + ttl,
    nonce: Buffer.from(new Uint8Array(16).fill(0x07)).toString("base64"),
  }
  return signCapCert(unsigned, iss.edPrivHex)
}

async function mintMember(
  iss: RootKeys,
  sub: RootKeys,
  nbf: number,
  collections: string[] = ["shared"],
): Promise<CapCert> {
  const unsigned: UnsignedCapCert = {
    v: 1,
    kind: "member",
    iss: iss.edPubHex,
    issUserId: iss.userId,
    sub: sub.edPubHex,
    subKem: sub.kemPubHex,
    subUserId: sub.userId,
    scope: { ops: ["read", "list"], collections, paths: ["shared/{identity}/*"] },
    nbf,
    exp: nbf + 3600,
    nonce: Buffer.from(new Uint8Array(16).fill(0x03)).toString("base64"),
  }
  return signCapCert(unsigned, iss.edPrivHex)
}

function capHeader(cert: unknown): string {
  return "Cap " + Buffer.from(JSON.stringify(cert)).toString("base64")
}

async function headers(cert: CapCert, signerPrivHex: string): Promise<Map<string, string>> {
  const req: SignableRequest = { method: "GET", pathAndQuery: PATH, body: new Uint8Array(0), host: HOST }
  const sig = await signRequest(req, signerPrivHex)
  return new Map([
    ["authorization", capHeader(cert)],
    ["x-starfish-sig", sig.sig],
    ["x-starfish-ts", String(sig.ts)],
    ["x-starfish-nonce", sig.nonce],
  ])
}

function run(
  h: Map<string, string>,
  opts: { nonceCache?: NonceCache; revocationStore?: RevocationStore } = {},
): Promise<string | null> {
  return authenticateMetaRequest({
    method: "GET",
    pathAndQuery: PATH,
    host: HOST,
    headers: (name: string) => h.get(name) ?? null,
    nonceCache: opts.nonceCache ?? createInMemoryNonceCache(),
    revocationStore: opts.revocationStore ?? createInMemoryRevocationStore(),
    pluginValidators: PLUGIN_VALIDATORS,
  })
}

const nowSec = () => Math.floor(Date.now() / 1000)

describe("authenticateMetaRequest", () => {
  it("accepts a device cap and binds the issuer identity", async () => {
    const root = makeRoot(0x10)
    const cert = await mintDevice(root, root, nowSec() - 10)
    expect(await run(await headers(cert, root.edPrivHex))).toBe(root.userId)
  })

  it("accepts a member cap and binds the subject identity", async () => {
    const alice = makeRoot(0x20)
    const bob = makeRoot(0x22)
    const cert = await mintMember(alice, bob, nowSec() - 10)
    expect(await run(await headers(cert, bob.edPrivHex))).toBe(bob.userId)
  })

  it("rejects an audience cap", async () => {
    const alice = makeRoot(0x30)
    const bob = makeRoot(0x32)
    const nbf = nowSec() - 10
    const unsigned: UnsignedCapCert = {
      v: 1,
      kind: "audience",
      iss: alice.edPubHex,
      issUserId: alice.userId,
      sub: "",
      scope: { ops: ["read"], collections: ["shared"], paths: ["shared/x"] },
      nbf,
      exp: nbf + 3600,
      nonce: Buffer.from(new Uint8Array(16).fill(0x09)).toString("base64"),
    }
    const cert = await signCapCert(unsigned, alice.edPrivHex)
    const req: SignableRequest = { method: "GET", pathAndQuery: PATH, body: new Uint8Array(0), host: HOST }
    const sig = await signRequest(req, bob.edPrivHex)
    const h = new Map([
      ["authorization", capHeader(cert)],
      ["x-starfish-sig", sig.sig],
      ["x-starfish-ts", String(sig.ts)],
      ["x-starfish-nonce", sig.nonce],
      ["x-starfish-pub", bob.edPubHex],
    ])
    expect(await run(h)).toBeNull()
  })

  it("rejects a bad request signature", async () => {
    const root = makeRoot(0x40)
    const cert = await mintDevice(root, root, nowSec() - 10)
    const h = await headers(cert, root.edPrivHex)
    h.set("x-starfish-sig", Buffer.from(new Uint8Array(64)).toString("base64"))
    expect(await run(h)).toBeNull()
  })

  it("rejects an expired cap", async () => {
    const root = makeRoot(0x50)
    const cert = await mintDevice(root, root, nowSec() - 7200, 3600)
    expect(await run(await headers(cert, root.edPrivHex))).toBeNull()
  })

  it("rejects a replayed nonce", async () => {
    const root = makeRoot(0x60)
    const cert = await mintDevice(root, root, nowSec() - 10)
    const h = await headers(cert, root.edPrivHex)
    const nonceCache = createInMemoryNonceCache()
    expect(await run(h, { nonceCache })).toBe(root.userId)
    expect(await run(h, { nonceCache })).toBeNull()
  })

  it("rejects a revoked cap", async () => {
    const root = makeRoot(0x70)
    const cert = await mintDevice(root, root, nowSec() - 10)
    const revocationStore: RevocationStore = {
      isRevoked: () => true,
      acceptList: () => ({ ok: true }),
    } as unknown as RevocationStore
    expect(await run(await headers(cert, root.edPrivHex), { revocationStore })).toBeNull()
  })

  it("rejects a forged member shape (multi-collection)", async () => {
    const alice = makeRoot(0x80)
    const bob = makeRoot(0x82)
    const cert = await mintMember(alice, bob, nowSec() - 10, ["a", "b"])
    expect(await run(await headers(cert, bob.edPrivHex))).toBeNull()
  })
})
