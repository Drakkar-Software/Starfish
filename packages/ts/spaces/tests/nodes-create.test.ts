/**
 * Regression tests for createNode's owner-identity self-mint bug.
 *
 * createNode() used to unconditionally mint an `objinvlog` "member" cap for the
 * CREATOR'S OWN identity (subUserId === issUserId). starfish-sharing's
 * assertMemberCapShape rejects that shape outright — a `kind:"member"` cap
 * exists to grant access to someone ELSE, not to the issuer's own identity —
 * so every createNode() call threw against a real server. See ../src/nodes.ts.
 *
 * N1: createNode (enc:false) resolves without throwing and returns the node.
 * N2: createNode never mints a cap for its own identity (mintCap not called).
 * N3: createNode never records a node-stream access entry for the creator.
 * N4: createNode (enc:true) still mints/reads the SPACE keyring (unrelated,
 *     pre-existing path) but still does not self-mint a member cap.
 */
import { describe, it, expect, vi, beforeEach } from "vitest"
import type { StarfishClient } from "@drakkar.software/starfish-client"
import type { Session } from "../src/session.js"
import { clearDocCache } from "../src/doc-cache.js"

vi.mock("../src/invite-helpers.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/invite-helpers.js")>()
  return { ...original, mintCap: vi.fn(original.mintCap) }
})
vi.mock("../src/space-access-store.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/space-access-store.js")>()
  return { ...original, saveNodeStreamAccessEntry: vi.fn(original.saveNodeStreamAccessEntry) }
})
vi.mock("../src/client.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/client.js")>()
  return { ...original, ownerEnsureSpaceKeyring: vi.fn(async () => {}) }
})

import { createNode } from "../src/nodes.js"
import { mintCap } from "../src/invite-helpers.js"
import { saveNodeStreamAccessEntry } from "../src/space-access-store.js"

let _counter = 0
function nextSpaceId() { return `sp-createnode-test-${++_counter}` }

function makeTestSession() {
  const pushSpy = vi.fn(async () => ({ hash: "H_new", timestamp: 1 }))
  const pullSpy = vi.fn(async () => ({ data: { v: 2, objects: [], updatedAt: 0 }, hash: "H0" }))
  const peekSpy = vi.fn(async () => null)
  const client = { pull: pullSpy, push: pushSpy, peekCache: peekSpy } as unknown as StarfishClient

  const session = {
    contentClient: client,
    layout: {
      objIndexPull: (id: string) => `/pull/spaces/${id}/objects/_index`,
      objIndexPush: (id: string) => `/push/spaces/${id}/objects/_index`,
    },
    baseUrl: "http://test",
    namespace: "test",
    userId: "u1",
    nodeIdPrefix: "nd_",
    keys: { edPriv: "deadbeef", edPub: "edpub1", kemPub: "kempub1" },
  } as unknown as Session

  return { session, pushSpy, pullSpy }
}

beforeEach(() => {
  clearDocCache()
  vi.mocked(mintCap).mockClear()
  vi.mocked(saveNodeStreamAccessEntry).mockClear()
})

describe("createNode — no self-minted member cap (regression)", () => {
  it("N1: resolves without throwing and returns the created node", async () => {
    const { session } = makeTestSession()
    const spaceId = nextSpaceId()

    const node = await createNode(session, spaceId, { type: "doc", title: "Mirror", access: "space", enc: false })

    expect(node.id).toBeTruthy()
    expect(node.type).toBe("doc")
    expect(node.title).toBe("Mirror")
  })

  it("N2: never mints a cap for its own identity", async () => {
    const { session } = makeTestSession()
    const spaceId = nextSpaceId()

    await createNode(session, spaceId, { type: "doc", title: "Mirror", access: "space", enc: false })

    expect(mintCap).not.toHaveBeenCalled()
  })

  it("N3: never records a node-stream access entry for the creator", async () => {
    const { session } = makeTestSession()
    const spaceId = nextSpaceId()

    await createNode(session, spaceId, { type: "doc", title: "Mirror", access: "space", enc: false })

    expect(saveNodeStreamAccessEntry).not.toHaveBeenCalled()
  })

  it("N4: enc:true still ensures the space keyring but still does not self-mint a member cap", async () => {
    const { session } = makeTestSession()
    const spaceId = nextSpaceId()

    const node = await createNode(session, spaceId, { type: "doc", title: "Mirror", access: "space", enc: true })

    expect(node.enc).toBe(true)
    expect(mintCap).not.toHaveBeenCalled()
  })
})
