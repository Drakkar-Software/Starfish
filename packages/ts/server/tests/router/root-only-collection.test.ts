/**
 * `rootOnly` collections: only the root device (a self-signed device cap,
 * `iss === sub`) may access them. Every paired/delegated device cap lacks
 * `ROLE_ROOT_DEVICE` and is rejected with 403 — on standalone pull/list/push
 * AND on bundle pulls (the bundle handler shares the same access decision as
 * `checkAuth`, so a rule added to one cannot silently skip the other).
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
import type { SyncConfig, CollectionConfig } from "../../src/config/schema.js"

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

interface Keys {
  edPrivHex: string
  edPubHex: string
  kemPubHex: string
  userId: string
}

function makeKeys(seed: number): Keys {
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

async function mintDeviceCert(
  iss: Keys,
  sub: Keys,
  collections: string[],
  nonceSeed: number,
): Promise<CapCert> {
  const nbf = Math.floor(Date.now() / 1000) - 10
  const unsigned: UnsignedCapCert = {
    v: 1,
    kind: "device",
    iss: iss.edPubHex,
    issUserId: iss.userId,
    sub: sub.edPubHex,
    subKem: sub.kemPubHex,
    scope: { ops: ["read", "list", "write"], collections, paths: ["**"] },
    nbf,
    exp: nbf + 3600,
    nonce: Buffer.from(new Uint8Array(16).fill(nonceSeed)).toString("base64"),
  }
  return signCapCert(unsigned, iss.edPrivHex)
}

/** Root device: self-signed cap (iss === sub). */
function rootCert(root: Keys, collections: string[], nonceSeed = 0x10): Promise<CapCert> {
  return mintDeviceCert(root, root, collections, nonceSeed)
}

/** Paired device: minted by the root for a separate device keypair (iss !== sub). */
function pairedCert(root: Keys, device: Keys, collections: string[], nonceSeed = 0x20): Promise<CapCert> {
  return mintDeviceCert(root, device, collections, nonceSeed)
}

const json = ["application/json"]

function collection(over: Partial<CollectionConfig> & Pick<CollectionConfig, "name" | "storagePath">): CollectionConfig {
  return {
    readRoles: [`cap:read:${over.name}`],
    writeRoles: [`cap:write:${over.name}`],
    encryption: "none",
    maxBodyBytes: 1_000_000,
    allowedMimeTypes: json,
    ...over,
  } as CollectionConfig
}

function makeConfig(): SyncConfig {
  return {
    version: 1,
    collections: [
      // Standalone rootOnly collection (also listable, so /list is exercised).
      collection({ name: "secret", storagePath: "secret/{slot}", rootOnly: true, listable: true }),
      // Standalone normal collection — must stay reachable by paired devices.
      collection({ name: "open", storagePath: "open/{slot}" }),
      // Bundle members sharing one storagePath: a normal member, a rootOnly
      // member, and a member requiring a role the paired device lacks.
      collection({ name: "pub", storagePath: "room/{rid}", bundle: "b" }),
      collection({ name: "sec", storagePath: "room/{rid}", bundle: "b", rootOnly: true }),
      collection({ name: "other", storagePath: "room/{rid}", bundle: "b" }),
    ],
  }
}

function makeApp(opts?: Partial<SyncRouterOptions>) {
  const resolver = createCapCertRoleResolver({
    nonceCache: createInMemoryNonceCache(),
    revocationStore: createInMemoryRevocationStore(),
    allowAnonymous: true,
    ...opts,
  })
  return createSyncRouter({
    store: new MemoryObjectStore(new Map()),
    config: makeConfig(),
    roleResolver: resolver,
  })
}

function capHeader(cert: CapCert): string {
  return "Cap " + Buffer.from(JSON.stringify(cert)).toString("base64")
}

async function signed(
  method: SignableRequest["method"],
  path: string,
  body: Uint8Array | undefined,
  edPrivHex: string,
  cert: CapCert,
): Promise<Record<string, string>> {
  const req: SignableRequest = { method, pathAndQuery: path, body, host: "localhost" }
  const sig = await signRequest(req, edPrivHex)
  const headers: Record<string, string> = {
    Authorization: capHeader(cert),
    "X-Starfish-Sig": sig.sig,
    "X-Starfish-Ts": String(sig.ts),
    "X-Starfish-Nonce": sig.nonce,
  }
  if (body) {
    headers["Content-Type"] = "application/json"
    // The cap-resolver rejects writes without a Content-Length (DoS guard).
    headers["Content-Length"] = String(body.length)
  }
  return headers
}

const PUSH_BODY = JSON.stringify({ data: { v: 1 }, baseHash: null })
const PUSH_BYTES = new TextEncoder().encode(PUSH_BODY)

describe("rootOnly collection — standalone pull/list/push", () => {
  it("root device can read, list, and write a rootOnly collection", async () => {
    const root = makeKeys(0x21)
    const cert = await rootCert(root, ["secret"])
    const app = makeApp()

    const pullPath = "/pull/secret/s1"
    const pullRes = await app.request(pullPath, {
      method: "GET",
      headers: await signed("GET", pullPath, undefined, root.edPrivHex, cert),
    })
    expect(pullRes.status).toBe(200)

    const listPath = "/list/secret"
    const listRes = await app.request(listPath, {
      method: "GET",
      headers: await signed("GET", listPath, undefined, root.edPrivHex, cert),
    })
    expect(listRes.status).toBe(200)

    const pushPath = "/push/secret/s1"
    const pushRes = await app.request(pushPath, {
      method: "POST",
      headers: await signed("POST", pushPath, PUSH_BYTES, root.edPrivHex, cert),
      body: PUSH_BODY,
    })
    expect(pushRes.status).toBe(200)
  })

  it("paired device is denied read, list, and write on a rootOnly collection", async () => {
    const root = makeKeys(0x31)
    const device = makeKeys(0x32)
    // Same scope.collections as the root cap, so the readRoles/writeRoles gate
    // alone would pass — only the rootOnly (ROLE_ROOT_DEVICE) gate rejects it.
    const cert = await pairedCert(root, device, ["secret"])
    const app = makeApp()

    const pullPath = "/pull/secret/s1"
    const pullRes = await app.request(pullPath, {
      method: "GET",
      headers: await signed("GET", pullPath, undefined, device.edPrivHex, cert),
    })
    expect(pullRes.status).toBe(403)

    const listPath = "/list/secret"
    const listRes = await app.request(listPath, {
      method: "GET",
      headers: await signed("GET", listPath, undefined, device.edPrivHex, cert),
    })
    expect(listRes.status).toBe(403)

    const pushPath = "/push/secret/s1"
    const pushRes = await app.request(pushPath, {
      method: "POST",
      headers: await signed("POST", pushPath, PUSH_BYTES, device.edPrivHex, cert),
      body: PUSH_BODY,
    })
    expect(pushRes.status).toBe(403)
  })

  it("anonymous is denied a rootOnly collection", async () => {
    const app = makeApp()
    const res = await app.request("/pull/secret/s1", { method: "GET" })
    expect(res.status).toBe(403)
  })

  it("a paired device still reaches a non-rootOnly collection", async () => {
    const root = makeKeys(0x41)
    const device = makeKeys(0x42)
    const cert = await pairedCert(root, device, ["open"])
    const app = makeApp()

    const path = "/pull/open/s1"
    const res = await app.request(path, {
      method: "GET",
      headers: await signed("GET", path, undefined, device.edPrivHex, cert),
    })
    expect(res.status).toBe(200)
  })
})

describe("rootOnly collection — bundle pull (shared access decision)", () => {
  it("a paired device's bundle pull omits the rootOnly member and any member it lacks a role for", async () => {
    const root = makeKeys(0x51)
    const device = makeKeys(0x52)
    // Holds roles for pub + sec (NOT other). sec is rootOnly, so it is excluded
    // by the rootOnly gate; other is excluded by the readRoles check.
    const cert = await pairedCert(root, device, ["pub", "sec"])
    const app = makeApp()

    const path = "/pull/room/r1"
    const res = await app.request(path, {
      method: "GET",
      headers: await signed("GET", path, undefined, device.edPrivHex, cert),
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as { collections: Record<string, unknown> }
    expect(Object.keys(body.collections).sort()).toEqual(["pub"])
  })

  it("the root device's bundle pull includes the rootOnly member", async () => {
    const root = makeKeys(0x61)
    const cert = await rootCert(root, ["pub", "sec", "other"])
    const app = makeApp()

    const path = "/pull/room/r1"
    const res = await app.request(path, {
      method: "GET",
      headers: await signed("GET", path, undefined, root.edPrivHex, cert),
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as { collections: Record<string, unknown> }
    expect(Object.keys(body.collections).sort()).toEqual(["other", "pub", "sec"])
  })
})
