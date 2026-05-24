/**
 * Member cap `{identity}` URL binding: a member cap from Alice to Bob
 * sets `auth.identity = bobUserId`. The route guard then requires
 * `params.identity === auth.identity`, so Bob's member cap can never
 * reach Alice's private namespace.
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
    edPrivHex: bytesToHex(edPriv),
    edPubHex: bytesToHex(edPub),
    kemPubHex: bytesToHex(kemPub),
    userId,
  }
}

async function mintMemberCert(
  iss: RootKeys,
  sub: RootKeys,
  collections: string[],
  paths: string[],
  ops: ("read" | "write" | "list")[] = ["read", "list", "write"],
  nonceSeed = 0x07,
): Promise<CapCert> {
  const nbf = Math.floor(Date.now() / 1000) - 10
  const unsigned: UnsignedCapCert = {
    v: 1,
    kind: "member",
    iss: iss.edPubHex,
    issUserId: iss.userId,
    sub: sub.edPubHex,
    subKem: sub.kemPubHex,
    subUserId: sub.userId,
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
        name: "shared-team",
        storagePath: "shared-team/{identity}/notes",
        readRoles: ["cap:read:shared-team", "self"],
        writeRoles: ["cap:write:shared-team", "self"],
        encryption: "none",
        maxBodyBytes: 1_000_000,
        allowedMimeTypes: ["application/json"],
      },
      {
        name: "private-notes",
        storagePath: "users/{identity}/private-notes",
        readRoles: ["self"],
        writeRoles: ["self"],
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
    // Accept `member` caps: the resolver is device-only by default, so the
    // member-cap shape validator must be wired for these binding tests.
    plugins: [sharingServerPlugin],
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
  // so the server-side resolver extracts host "localhost" from c.req.url.
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

describe("member cap {identity} URL binding", () => {
  it("Alice's member cap to Bob lets Bob access shared-team scoped to his own identity", async () => {
    const alice = makeRoot(0xa1)
    const bob = makeRoot(0xa2)
    const cert = await mintMemberCert(
      alice,
      bob,
      ["shared-team"],
      ["shared-team/{identity}/notes"],
    )

    const app = makeApp()
    const path = `/pull/shared-team/${bob.userId}/notes`
    const headers = await signedHeaders("GET", path, undefined, bob.edPrivHex, encodeCapHeader(cert))
    const res = await app.request(path, { method: "GET", headers })
    expect(res.status).toBe(200)
  })

  it("Bob's member cap CANNOT reach Alice's private namespace", async () => {
    const alice = makeRoot(0xb1)
    const bob = makeRoot(0xb2)
    const cert = await mintMemberCert(
      alice,
      bob,
      ["shared-team"],
      ["shared-team/{identity}/notes"],
    )

    const app = makeApp()
    // Attempt to read alice's private-notes (params.identity = alice.userId)
    // with bob's member cap (auth.identity = bob.userId).
    const path = `/pull/users/${alice.userId}/private-notes`
    const headers = await signedHeaders("GET", path, undefined, bob.edPrivHex, encodeCapHeader(cert))
    const res = await app.request(path, { method: "GET", headers })
    expect(res.status).toBe(403)
  })

  it("Bob's member cap cannot pose as Alice in the shared-team path", async () => {
    const alice = makeRoot(0xc1)
    const bob = makeRoot(0xc2)
    const cert = await mintMemberCert(
      alice,
      bob,
      ["shared-team"],
      ["shared-team/{identity}/notes"],
    )

    const app = makeApp()
    // Request targets alice's slot of shared-team. Bob's cap has
    // auth.identity = bob.userId, so the identity binding rejects.
    const path = `/pull/shared-team/${alice.userId}/notes`
    const headers = await signedHeaders("GET", path, undefined, bob.edPrivHex, encodeCapHeader(cert))
    const res = await app.request(path, { method: "GET", headers })
    expect(res.status).toBe(403)
  })
})
