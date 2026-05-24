import { describe, it, expect, beforeAll, vi } from "vitest"
import { webcrypto } from "node:crypto"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import type { CapCert } from "@drakkar.software/starfish-protocol"
import { deriveRootIdentity } from "../src/identity.js"
import { mintDeviceCap, scopes } from "../src/cap-mint.js"
import {
  addDeviceEntry,
  devicesPathFor,
  listDevices,
  removeDeviceEntry,
  type Directory,
} from "../src/directory.js"
import { ConflictError, StarfishHttpError, type StarfishClient } from "@drakkar.software/starfish-client"

beforeAll(() => {
  configurePlatform({
    crypto: webcrypto as unknown as Crypto,
    base64: {
      encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
      decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
    },
  })
})

/** In-memory mock StarfishClient — stores directory docs keyed by storage path. */
function makeMockClient() {
  const store = new Map<string, { data: Directory; hash: string }>()
  let counter = 0

  function stripPrefix(routePath: string, prefix: string): string {
    if (!routePath.startsWith(prefix)) {
      throw new Error(`expected path to start with ${prefix}, got ${routePath}`)
    }
    return routePath.slice(prefix.length)
  }

  const client = {
    pull: vi.fn(async (routePath: string) => {
      const storagePath = stripPrefix(routePath, "/pull/")
      const entry = store.get(storagePath)
      if (!entry) throw new StarfishHttpError(404, "not found")
      return {
        data: entry.data as unknown as Record<string, unknown>,
        hash: entry.hash,
        timestamp: 1000,
      }
    }),
    push: vi.fn(
      async (
        routePath: string,
        data: Record<string, unknown>,
        baseHash: string | null,
      ) => {
        const storagePath = stripPrefix(routePath, "/push/")
        const current = store.get(storagePath)
        if (current && baseHash !== current.hash) {
          throw new ConflictError()
        }
        if (!current && baseHash !== null) {
          throw new ConflictError()
        }
        counter += 1
        const hash = `h${counter}`
        store.set(storagePath, { data: data as unknown as Directory, hash })
        return { hash, timestamp: 2000 }
      },
    ),
  } as unknown as StarfishClient

  return { client, store }
}

describe("devicesPathFor", () => {
  it("returns users/<id>/_devices", () => {
    expect(devicesPathFor("abc1234567890def")).toBe(
      "users/abc1234567890def/_devices",
    )
  })
})

describe("addDeviceEntry + listDevices", () => {
  it("appends a device cap to an empty directory", async () => {
    const alice = await deriveRootIdentity("alice-dir-pass")
    const cert = await mintDeviceCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: alice.keys.edPub, kemPubHex: alice.keys.kemPub },
      scopes.rootAll(),
    )
    const { client, store } = makeMockClient()
    await addDeviceEntry(client, alice.userId, cert, { label: "Alice's iPhone" })

    const stored = store.get(devicesPathFor(alice.userId))!
    expect(stored.data.entries).toHaveLength(1)
    expect(stored.data.entries[0]!.nonce).toBe(cert.nonce)
    expect(stored.data.entries[0]!.sub).toBe(cert.sub)
    expect(stored.data.entries[0]!.label).toBe("Alice's iPhone")

    const listed = await listDevices(client, alice.userId)
    expect(listed).toHaveLength(1)
    expect(listed[0]!.nonce).toBe(cert.nonce)
  })

  it("upserts: overwrites a stale entry with the same nonce", async () => {
    const alice = await deriveRootIdentity("alice-upsert-pass")
    const cert = await mintDeviceCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: alice.keys.edPub, kemPubHex: alice.keys.kemPub },
      scopes.rootAll(),
    )
    const { client, store } = makeMockClient()
    await addDeviceEntry(client, alice.userId, cert, { label: "first" })
    await addDeviceEntry(client, alice.userId, cert, { label: "second" })

    const stored = store.get(devicesPathFor(alice.userId))!
    expect(stored.data.entries).toHaveLength(1)
    expect(stored.data.entries[0]!.label).toBe("second")
  })

  it("rejects a member cap with a clear error", async () => {
    const alice = await deriveRootIdentity("alice-bad-kind-pass")
    // addDeviceEntry dispatches purely on `cert.kind`; a minimal member-kind
    // object is enough to exercise the guard without depending on the sharing
    // extension's mintMemberCap.
    const memberCert = {
      v: 1,
      kind: "member",
      iss: alice.keys.edPub,
      issUserId: alice.userId,
      sub: alice.keys.edPub,
      subKem: alice.keys.kemPub,
      subUserId: alice.userId,
      scope: { ops: ["read"], collections: ["shared"], paths: ["shared/**"] },
      nbf: 0,
      exp: 0,
      nonce: "AAAAAAAAAAAAAAAAAAAAAA==",
      sig: "",
    } as unknown as CapCert
    const { client } = makeMockClient()
    await expect(
      addDeviceEntry(client, alice.userId, memberCert),
    ).rejects.toThrow(/kind="member"/)
  })

  it("listDevices filters expired entries by default", async () => {
    const alice = await deriveRootIdentity("alice-expired-pass")
    const cert = await mintDeviceCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: alice.keys.edPub, kemPubHex: alice.keys.kemPub },
      scopes.rootAll(),
    )
    const { client, store } = makeMockClient()
    await addDeviceEntry(client, alice.userId, cert)

    // Mutate stored entry to past expiry
    const path = devicesPathFor(alice.userId)
    const stored = store.get(path)!
    stored.data.entries[0]!.exp = Math.floor(Date.now() / 1000) - 1000

    const visible = await listDevices(client, alice.userId)
    expect(visible).toHaveLength(0)
    const allWithExpired = await listDevices(client, alice.userId, {
      includeExpired: true,
    })
    expect(allWithExpired).toHaveLength(1)
  })

  it("listDevices filters revoked nonces when provided", async () => {
    const alice = await deriveRootIdentity("alice-revoked-pass")
    const cert = await mintDeviceCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: alice.keys.edPub, kemPubHex: alice.keys.kemPub },
      scopes.rootAll(),
    )
    const { client } = makeMockClient()
    await addDeviceEntry(client, alice.userId, cert)

    const visible = await listDevices(client, alice.userId, {
      revokedNonces: new Set([cert.nonce]),
    })
    expect(visible).toHaveLength(0)
  })

  it("returns empty list when directory does not exist yet", async () => {
    const { client } = makeMockClient()
    const out = await listDevices(client, "noone")
    expect(out).toEqual([])
  })
})

describe("removeDeviceEntry", () => {
  it("removes by nonce and returns true; subsequent removal returns false", async () => {
    const alice = await deriveRootIdentity("alice-rem-pass")
    const cert = await mintDeviceCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: alice.keys.edPub, kemPubHex: alice.keys.kemPub },
      scopes.rootAll(),
    )
    const { client } = makeMockClient()
    await addDeviceEntry(client, alice.userId, cert)

    const removed = await removeDeviceEntry(client, alice.userId, cert.nonce)
    expect(removed).toBe(true)

    const removedAgain = await removeDeviceEntry(client, alice.userId, cert.nonce)
    expect(removedAgain).toBe(false)
  })

  it("returns false when directory does not exist yet", async () => {
    const { client } = makeMockClient()
    const removed = await removeDeviceEntry(client, "ghost", "noncexyz")
    expect(removed).toBe(false)
  })
})

describe("baseHash retry on concurrent writes", () => {
  it("retries when the first push fails with ConflictError", async () => {
    const alice = await deriveRootIdentity("alice-conflict-pass")
    const cert = await mintDeviceCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: alice.keys.edPub, kemPubHex: alice.keys.kemPub },
      scopes.rootAll(),
    )
    const { client, store } = makeMockClient()
    const path = devicesPathFor(alice.userId)

    // Seed an existing directory doc with a known hash.
    store.set(path, {
      data: {
        v: 1,
        entries: [
          {
            nonce: "PLACEHOLDER",
            sub: alice.keys.edPub,
            subKem: alice.keys.kemPub,
            scope: cert.scope,
            nbf: cert.nbf,
            exp: cert.exp,
            addedAt: Math.floor(Date.now() / 1000),
          },
        ],
      },
      hash: "h-initial",
    })

    // Intercept push: first call gets a fake conflict; subsequent calls fall
    // through to the underlying mock implementation so the retry succeeds.
    const pushMock = client.push as unknown as ReturnType<typeof vi.fn>
    const realPush = pushMock.getMockImplementation()!
    let pushCount = 0
    pushMock.mockImplementation(
      async (routePath: string, data: Record<string, unknown>, baseHash: string | null) => {
        pushCount += 1
        if (pushCount === 1) {
          throw new ConflictError()
        }
        return realPush(routePath, data, baseHash)
      },
    )

    await addDeviceEntry(client, alice.userId, cert)

    expect(pushCount).toBeGreaterThan(1)
    const stored = store.get(path)!
    expect(stored.data.entries.map((e) => e.nonce).sort()).toEqual(
      ["PLACEHOLDER", cert.nonce].sort(),
    )
  })
})

describe("entry shape", () => {
  it("copies the cap's scope/nbf/exp verbatim and stamps addedAt", async () => {
    const alice = await deriveRootIdentity("alice-shape-pass")
    const before = Math.floor(Date.now() / 1000)
    const cert = await mintDeviceCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: alice.keys.edPub, kemPubHex: alice.keys.kemPub },
      scopes.rootAll(),
    )
    const { client } = makeMockClient()
    await addDeviceEntry(client, alice.userId, cert, {
      label: "test-host",
      addedBy: alice.keys.edPub,
    })
    const entries = await listDevices(client, alice.userId, {
      includeExpired: true,
    })
    expect(entries).toHaveLength(1)
    const e = entries[0]!
    expect(e.scope).toEqual(cert.scope)
    expect(e.nbf).toBe(cert.nbf)
    expect(e.exp).toBe(cert.exp)
    expect(e.label).toBe("test-host")
    expect(e.addedBy).toBe(alice.keys.edPub)
    expect(e.addedAt).toBeGreaterThanOrEqual(before)
  })
})
