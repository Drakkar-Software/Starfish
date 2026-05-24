import { describe, it, expect, beforeAll, vi } from "vitest"
import { webcrypto } from "node:crypto"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { deriveRootIdentity, mintDeviceCap, scopes as identityScopes } from "@drakkar.software/starfish-identities"
import { mintMemberCap, scopes } from "../src/cap-mint.js"
import {
  addMemberEntry,
  listMembers,
  membersPathFor,
  removeMemberEntry,
  publishMemberCap,
  fetchMemberCaps,
  fetchMyMemberCap,
  unpublishMemberCap,
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

/** In-memory mock StarfishClient. */
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

describe("membersPathFor", () => {
  it("returns <col>/_members for a flat collection name", () => {
    expect(membersPathFor("shared-notes")).toBe("shared-notes/_members")
  })

  it("preserves nested collection paths", () => {
    expect(membersPathFor("users/owner-id/notes")).toBe(
      "users/owner-id/notes/_members",
    )
  })
})

describe("addMemberEntry + listMembers", () => {
  it("appends a member cap into <col>/_members", async () => {
    const alice = await deriveRootIdentity("alice-mem-pass")
    const bob = await deriveRootIdentity("bob-mem-pass")
    const cert = await mintMemberCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
      "shared-notes",
      scopes.writer("shared-notes"),
    )
    const { client, store } = makeMockClient()
    await addMemberEntry(client, "shared-notes", cert, { label: "Bob" })

    const stored = store.get(membersPathFor("shared-notes"))!
    expect(stored.data.entries).toHaveLength(1)
    expect(stored.data.entries[0]!.subUserId).toBe(bob.userId)
    expect(stored.data.entries[0]!.label).toBe("Bob")

    const listed = await listMembers(client, "shared-notes")
    expect(listed).toHaveLength(1)
    expect(listed[0]!.subUserId).toBe(bob.userId)
  })

  it("supports nested per-owner collection paths", async () => {
    const alice = await deriveRootIdentity("alice-nested-pass")
    const bob = await deriveRootIdentity("bob-nested-pass")
    const cert = await mintMemberCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
      "shared-notes",
      scopes.writer("shared-notes"),
    )
    const collectionPath = `users/${alice.userId}/shared-notes`
    const { client, store } = makeMockClient()
    await addMemberEntry(client, collectionPath, cert)

    expect(store.has(`${collectionPath}/_members`)).toBe(true)
  })

  it("rejects a device cap with a clear error", async () => {
    const alice = await deriveRootIdentity("alice-bad-mem-pass")
    const deviceCert = await mintDeviceCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: alice.keys.edPub, kemPubHex: alice.keys.kemPub },
      identityScopes.rootAll(),
    )
    const { client } = makeMockClient()
    await expect(
      addMemberEntry(client, "shared-notes", deviceCert),
    ).rejects.toThrow(/kind="device"/)
  })
})

describe("removeMemberEntry", () => {
  it("removes a member entry by nonce", async () => {
    const alice = await deriveRootIdentity("alice-remmem-pass")
    const bob = await deriveRootIdentity("bob-remmem-pass")
    const cert = await mintMemberCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
      "shared",
      scopes.writer("shared"),
    )
    const { client } = makeMockClient()
    await addMemberEntry(client, "shared", cert)
    expect(await removeMemberEntry(client, "shared", cert.nonce)).toBe(true)
    expect(await listMembers(client, "shared")).toHaveLength(0)
  })

  it("is an idempotent no-op when the nonce is not in the roster", async () => {
    // A retried/duplicate revoke (or removing an already-evicted member) must not error
    // or churn the directory — it returns false and leaves the roster intact.
    const alice = await deriveRootIdentity("alice-rem-noop-pass")
    const bob = await deriveRootIdentity("bob-rem-noop-pass")
    const cert = await mintMemberCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
      "shared",
      scopes.writer("shared"),
    )
    const { client } = makeMockClient()
    await addMemberEntry(client, "shared", cert)
    expect(await removeMemberEntry(client, "shared", "no-such-nonce")).toBe(false)
    expect(await listMembers(client, "shared")).toHaveLength(1)
  })
})

describe("published member caps", () => {
  async function makeMemberCap() {
    const alice = await deriveRootIdentity("alice-pub-pass")
    const bob = await deriveRootIdentity("bob-pub-pass")
    const cert = await mintMemberCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
      "shared-board",
      scopes.writer("shared-board"),
    )
    return { alice, bob, cert }
  }

  it("publishMemberCap stores the full signed cap; fetchMyMemberCap returns it verbatim", async () => {
    const { bob, cert } = await makeMemberCap()
    const { client, store } = makeMockClient()
    await publishMemberCap(client, "shared-board", cert, { label: "Bob" })

    // The stored entry carries the usable, signed cap (not just a projection).
    const entry = store.get(membersPathFor("shared-board"))!.data.entries[0]!
    expect(entry.cert).toEqual(cert)
    expect(entry.cert!.sig).toBe(cert.sig)

    const mine = await fetchMyMemberCap(client, "shared-board", bob.keys.edPub)
    expect(mine).toEqual(cert)
  })

  it("fetchMemberCaps returns every published cap; fetchMyMemberCap filters by sub", async () => {
    const a = await makeMemberCap()
    const carol = await deriveRootIdentity("carol-pub-pass")
    const carolCert = await mintMemberCap(
      a.alice.keys.edPriv,
      a.alice.keys.edPub,
      { edPubHex: carol.keys.edPub, kemPubHex: carol.keys.kemPub, userIdHex: carol.userId },
      "shared-board",
      scopes.readOnly("shared-board"),
    )
    const { client } = makeMockClient()
    await publishMemberCap(client, "shared-board", a.cert)
    await publishMemberCap(client, "shared-board", carolCert)

    const all = await fetchMemberCaps(client, "shared-board")
    expect(all).toHaveLength(2)
    const carolFetched = await fetchMyMemberCap(client, "shared-board", carol.keys.edPub)
    expect(carolFetched!.sub).toBe(carol.keys.edPub)
  })

  it("fetchMyMemberCap returns null when no cap is published for that key", async () => {
    const { cert } = await makeMemberCap()
    const stranger = await deriveRootIdentity("stranger-pub-pass")
    const { client } = makeMockClient()
    await publishMemberCap(client, "shared-board", cert)
    expect(
      await fetchMyMemberCap(client, "shared-board", stranger.keys.edPub),
    ).toBeNull()
    // also empty when the list does not exist yet
    expect(await fetchMyMemberCap(client, "absent-col", stranger.keys.edPub)).toBeNull()
  })

  it("unpublishMemberCap removes the published cap by nonce", async () => {
    const { bob, cert } = await makeMemberCap()
    const { client } = makeMockClient()
    await publishMemberCap(client, "shared-board", cert)
    expect(await unpublishMemberCap(client, "shared-board", cert.nonce)).toBe(true)
    expect(await fetchMyMemberCap(client, "shared-board", bob.keys.edPub)).toBeNull()
  })
})

describe("directory churn / convergence", () => {
  it("upserts by nonce — re-adding the same cap does not duplicate the entry", async () => {
    const alice = await deriveRootIdentity("alice-churn-dup-pass")
    const bob = await deriveRootIdentity("bob-churn-dup-pass")
    const cert = await mintMemberCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
      "shared",
      scopes.writer("shared"),
    )
    const { client } = makeMockClient()
    await addMemberEntry(client, "shared", cert, { label: "Bob" })
    await addMemberEntry(client, "shared", cert, { label: "Bob (again)" })

    const listed = await listMembers(client, "shared")
    expect(listed).toHaveLength(1)
    expect(listed[0]!.label).toBe("Bob (again)") // last write wins on the same nonce
  })

  it("converges on present after add → remove → re-add of the same nonce", async () => {
    const alice = await deriveRootIdentity("alice-churn-readd-pass")
    const bob = await deriveRootIdentity("bob-churn-readd-pass")
    const cert = await mintMemberCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
      "shared",
      scopes.writer("shared"),
    )
    const { client } = makeMockClient()
    await addMemberEntry(client, "shared", cert)
    expect(await removeMemberEntry(client, "shared", cert.nonce)).toBe(true)
    expect(await listMembers(client, "shared")).toHaveLength(0)

    await addMemberEntry(client, "shared", cert)
    const listed = await listMembers(client, "shared")
    expect(listed).toHaveLength(1)
    expect(listed[0]!.subUserId).toBe(bob.userId)
  })
})
