/**
 * Authority inheritance: a `kind: "device"` cap inherits the issuer's authority.
 * `auth.identity` is set to `issUserId`, NOT to whatever path identity the
 * request happens to target. This is the cryptographic root of
 * "device of A cannot access B's data".
 *
 * Exercises the `{identity}` URL binding and the `scope.paths` glob in
 * the cap-resolver.
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
import { createSyncRouter, type SyncRouterOptions } from "../../src/router/route-builder.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import { createCapCertRoleResolver } from "../../src/router/cap-resolver.js"
import { createInMemoryNonceCache } from "../../src/auth/nonce-cache.js"
import { createInMemoryRevocationStore } from "../../src/auth/revocation-store.js"
import type { SyncConfig } from "../../src/config/schema.js"

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
  return {
    edPriv,
    edPub,
    edPrivHex: bytesToHex(edPriv),
    edPubHex: bytesToHex(edPub),
    kemPubHex: bytesToHex(kemPub),
    userId,
  }
}

async function mintDeviceCert(
  iss: RootKeys,
  sub: RootKeys,
  paths: string[],
  collections: string[] = ["data"],
  ops: ("read" | "write" | "list")[] = ["read", "list", "write"],
  nonceSeed = 0x07,
): Promise<CapCert> {
  const nbf = Math.floor(Date.now() / 1000) - 10
  const unsigned: UnsignedCapCert = {
    v: 1,
    kind: "device",
    issAlg: "ed25519",
    iss: iss.edPubHex,
    issUserId: iss.userId,
    sub: sub.edPubHex,
    subKem: sub.kemPubHex,
    scope: { ops, collections, paths },
    nbf,
    exp: nbf + 3600,
    nonce: Buffer.from(new Uint8Array(16).fill(nonceSeed)).toString("base64"),
  }
  return signCapCert(unsigned, iss.edPrivHex)
}

function makeConfig(): SyncConfig {
  return {
    version: 1,
    collections: [
      {
        name: "data",
        storagePath: "users/{identity}/data",
        readRoles: ["cap:read:data", "self"],
        writeRoles: ["cap:write:data", "self"],
        encryption: "none",
        maxBodyBytes: 1_000_000,
        allowedMimeTypes: ["application/json"],
      },
    ],
  }
}

function makeApp(opts?: Partial<SyncRouterOptions>) {
  const store = new MemoryObjectStore(new Map())
  const config = makeConfig()
  const resolver = createCapCertRoleResolver({
    nonceCache: createInMemoryNonceCache(),
    revocationStore: createInMemoryRevocationStore(),
    allowAnonymous: true,
    ...opts,
  })
  return createSyncRouter({
    store,
    config,
    roleResolver: resolver,
  })
}

function encodeCapHeader(cert: unknown): string {
  return "Cap " + Buffer.from(JSON.stringify(cert)).toString("base64")
}

async function signedHeaders(
  method: SignableRequest["method"],
  pathAndQuery: string,
  body: Uint8Array | undefined,
  edPrivHex: string,
  certHeader: string,
): Promise<Record<string, string>> {
  // Hono's app.request("/path") synthesizes a URL like "http://localhost/path",
  // so the server-side resolver will extract host "localhost" from c.req.url.
  // The signed canonical input MUST bind the same host or sig verify fails.
  const req: SignableRequest = { method, pathAndQuery, body, host: "localhost" }
  const sig = await signRequest(req, edPrivHex)
  return {
    Authorization: certHeader,
    "X-Starfish-Sig": sig.sig,
    "X-Starfish-Ts": String(sig.ts),
    "X-Starfish-Nonce": sig.nonce,
  }
}

describe("authority inheritance — device cap binds auth.identity to issUserId", () => {
  it("device cap can pull from issuer's own storage path", async () => {
    const alice = makeRoot(0x21)
    const aliceDev = makeRoot(0x22)
    const cert = await mintDeviceCert(alice, aliceDev, ["users/*/data"])

    const app = makeApp()
    const path = `/pull/users/${alice.userId}/data`
    const headers = await signedHeaders("GET", path, undefined, aliceDev.edPrivHex, encodeCapHeader(cert))
    const res = await app.request(path, { method: "GET", headers })
    expect(res.status).toBe(200)
    const body = (await res.json()) as { data: unknown; hash: string }
    expect(body.data).toEqual({})
    expect(typeof body.hash).toBe("string")
  })

  it("device cap canNOT pull from a different user's path (params.identity != auth.identity)", async () => {
    const alice = makeRoot(0x31)
    const bob = makeRoot(0x32)
    const aliceDev = makeRoot(0x33)
    const cert = await mintDeviceCert(alice, aliceDev, ["users/*/data"])

    const app = makeApp()
    const path = `/pull/users/${bob.userId}/data`
    const headers = await signedHeaders("GET", path, undefined, aliceDev.edPrivHex, encodeCapHeader(cert))
    const res = await app.request(path, { method: "GET", headers })
    expect(res.status).toBe(403)
  })

  it("adversarial path scope cannot override identity binding", async () => {
    // Even when the cap's scope.paths explicitly lists bob's namespace,
    // auth.identity is server-controlled (= issUserId for a device cap),
    // so the identity-vs-params check still rejects.
    const alice = makeRoot(0x41)
    const bob = makeRoot(0x42)
    const aliceDev = makeRoot(0x43)
    const cert = await mintDeviceCert(alice, aliceDev, [
      `users/${bob.userId}/data`,
    ])

    const app = makeApp()
    const path = `/pull/users/${bob.userId}/data`
    const headers = await signedHeaders("GET", path, undefined, aliceDev.edPrivHex, encodeCapHeader(cert))
    const res = await app.request(path, { method: "GET", headers })
    expect(res.status).toBe(403)
  })

  it("device cap with mismatched scope.paths is rejected even on its own identity", async () => {
    // Cap allows only `notes/*` paths but request targets `users/<alice>/data`.
    // Even though identity matches, scope.paths denies access.
    const alice = makeRoot(0x51)
    const aliceDev = makeRoot(0x52)
    const cert = await mintDeviceCert(alice, aliceDev, ["notes/*"])

    const app = makeApp()
    const path = `/pull/users/${alice.userId}/data`
    const headers = await signedHeaders("GET", path, undefined, aliceDev.edPrivHex, encodeCapHeader(cert))
    const res = await app.request(path, { method: "GET", headers })
    expect(res.status).toBe(403)
  })
})
