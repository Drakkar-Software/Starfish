/**
 * Regression tests for `getNodeAccess`'s handle cache key.
 *
 * The key was `${spaceId}:${nodeId}` — neither the resolving identity nor the
 * node's encryption tier. Two distinct handles therefore collided:
 *
 * C1: two identities in one process. The second caller was served the first's
 *     capability-bearing client, i.e. someone else's credential.
 * C2: one node's plaintext and encrypted views. Resolving the ENCRYPTED view
 *     first poisoned the plaintext one with its encryptor — and a caller that
 *     seals on `encryptor != null` (starfish-replica's `pushNodeDoc` does)
 *     would then write ciphertext into a collection the server declares
 *     `encryption:"none"`, e.g. `objpub`, whose reads are world-readable. The
 *     push succeeds; the world gets an opaque blob.
 *
 * C2 is the mirror image of the Python-side hazard fixed in
 * `starfish_spaces/space_access.py` (there the resolver had no tier argument at
 * all; here it had one but the cache discarded it).
 *
 * The plaintext branch itself (`if (!node.enc) return makeHandle(client, null, …)`)
 * was always correct in TS — these tests pin that the cache cannot route around it.
 */
import { describe, it, expect, beforeEach } from "vitest"
import { generateDeviceKeys } from "@drakkar.software/starfish-identities"
import { getNodeAccess, clearNodeAccessCache } from "../src/space-access.js"
import { clearSpaceAccessStore } from "../src/space-access-store.js"
import type { Session } from "../src/session.js"

const SPACE = "sp-1"
const NODE = "nd-1"

function fakeSession(userId: string): Session {
  // Real keys: the encrypted branch genuinely mints a space keyring, so the
  // encrypted-vs-plaintext comparison below exercises the real resolution rather
  // than two failed lookups that would both be null for the wrong reason.
  const keys = generateDeviceKeys()
  const store = new Map<string, unknown>()
  const client = {
    pull: async (path: string) => ({ data: store.get(path) ?? {}, hash: null }),
    push: async (path: string, payload: unknown) => {
      store.set(path.replace("/push/", "/pull/"), payload)
      return { hash: "h1", timestamp: 1 }
    },
    peekCache: async () => null,
  }
  return {
    userId,
    name: userId,
    keys,
    contentCap: null,
    contentClient: client,
    accountClient: client,
    ownerEdPub: keys.edPub,
    baseUrl: "http://test",
    namespace: "test",
    nodeIdPrefix: "nd_",
    spaceIdPrefix: "sp_",
    layout: {
      keyringPull: (id: string) => `/pull/spaces/${id}/_keyring`,
      keyringPush: (id: string) => `/push/spaces/${id}/_keyring`,
      nodeKeyringPull: (s: string, n: string) => `/pull/spaces/${s}/objects/n/${n}/_keyring`,
      nodeKeyringPush: (s: string, n: string) => `/push/spaces/${s}/objects/n/${n}/_keyring`,
    },
  } as unknown as Session
}

beforeEach(() => {
  clearNodeAccessCache()
  clearSpaceAccessStore()
})

describe("getNodeAccess cache key", () => {
  it("C2: a plaintext node is never served the encrypted view's handle", async () => {
    const session = fakeSession("user-a")

    const encrypted = await getNodeAccess(SPACE, NODE, { access: "space", enc: true }, session)
    const plaintext = await getNodeAccess(SPACE, NODE, { access: "public", enc: false }, session)

    expect(plaintext).not.toBe(encrypted)
    expect(plaintext.encryptor).toBeNull()
  })

  it("C2: and not in the other order either", async () => {
    const session = fakeSession("user-a")

    const plaintext = await getNodeAccess(SPACE, NODE, { access: "public", enc: false }, session)
    const encrypted = await getNodeAccess(SPACE, NODE, { access: "space", enc: true }, session)

    expect(plaintext.encryptor).toBeNull()
    expect(encrypted).not.toBe(plaintext)
  })

  it("C1: two identities do not share a handle for the same node", async () => {
    const a = await getNodeAccess(SPACE, NODE, { access: "public", enc: false }, fakeSession("user-a"))
    const b = await getNodeAccess(SPACE, NODE, { access: "public", enc: false }, fakeSession("user-b"))

    expect(a).not.toBe(b)
  })

  it("still caches a genuine repeat — same identity, same node, same tier", async () => {
    const session = fakeSession("user-a")

    const first = await getNodeAccess(SPACE, NODE, { access: "public", enc: false }, session)
    const second = await getNodeAccess(SPACE, NODE, { access: "public", enc: false }, session)

    expect(second).toBe(first)
  })

  it("omitting enc is the plaintext tier, matching what createNode stores", async () => {
    // createNode writes `enc: enc || undefined`, so a plaintext node has no `enc`
    // key at all. It must key to the same slot as an explicit `enc: false`.
    const session = fakeSession("user-a")

    const implicit = await getNodeAccess(SPACE, NODE, { access: "public" }, session)
    const explicit = await getNodeAccess(SPACE, NODE, { access: "public", enc: false }, session)

    expect(explicit).toBe(implicit)
    expect(implicit.encryptor).toBeNull()
  })

  it("distinct nodes never share a handle", async () => {
    const session = fakeSession("user-a")

    const one = await getNodeAccess(SPACE, "nd-a", { access: "public" }, session)
    const two = await getNodeAccess(SPACE, "nd-b", { access: "public" }, session)

    expect(one).not.toBe(two)
  })
})
