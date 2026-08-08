/**
 * Tests for `createSpaceMirrorChannel` against a fake `SpacePort` — an
 * in-memory, path/id-keyed fake (no `vi.mock`), matching this monorepo's
 * fake-client idiom (see `packages/ts/sharing/tests/evict.test.ts`).
 */
import { describe, expect, it, vi } from "vitest"
import {
  createSpaceMirrorChannel,
  type SpaceMirrorCollection,
} from "../src/space/mirror-channel.js"
import { REPLICATOR_CTX, type ReplicaCallContext } from "../src/channel.js"
import type { CreateNodeInput, NodeAccessHandle, Session, SpacePort } from "../src/space/port.js"

interface FakeNode {
  id: string
  type: string
  /** Stored access axis, recorded exactly the way `starfish-spaces`'
   *  `addObject` records it: OMITTED when it is the default `"space"`. The
   *  channel's flip detection reads these back off `readObjectTree`, so a fake
   *  that stored them verbatim would hide the "absent means default"
   *  normalization the real index forces. */
  access?: string
  /** Stored encryption axis. Omitted when false, same as the real index. */
  enc?: boolean
}

/** One CAS push the channel performed, recorded in order — enough to assert
 *  BOTH what was written and under which access mode, which is the whole point
 *  of the tier tests: a "public" write that actually went out as
 *  `access:"space"` looks identical if you only inspect `nodeContent`. */
interface FakePush {
  nodeId: string
  access: string | undefined
  enc: boolean | undefined
  pullPath: string
  pushPath: string
  data: Record<string, unknown> | null
}

function makeFakePort() {
  let spaceCounter = 0
  let nodeCounter = 0
  const spacesByName = new Map<string, { id: string; name: string }>()
  const nodesBySpace = new Map<string, Map<string, FakeNode>>()
  const nodeContent = new Map<string, Record<string, unknown>>()
  const pushes: FakePush[] = []

  const createSpace = vi.fn(async (_session: Session, name: string) => {
    const id = `space-${++spaceCounter}`
    const space = { id, name }
    spacesByName.set(name, space)
    nodesBySpace.set(id, new Map())
    return space
  })

  const createNode = vi.fn(async (_session: Session, spaceId: string, input: CreateNodeInput) => {
    const id = `node-${++nodeCounter}`
    const node: FakeNode = {
      id,
      type: input.type,
      ...(input.access && input.access !== "space" ? { access: input.access } : {}),
      ...(input.enc ? { enc: true } : {}),
    }
    nodesBySpace.get(spaceId)!.set(id, node)
    return node
  })

  /** Patch a stored node's axes the way the real index does — and, crucially,
   *  with the SAME normalization `createNode` above applies: `access` dropped
   *  when it is `"space"`, `enc` dropped when false. A fake that stored the
   *  patch verbatim would make a patched node distinguishable from one created
   *  at that tier, and the next cycle's stored-vs-configured comparison would
   *  read the difference as a fresh flip. */
  const setNodeAccess = vi.fn(
    async (
      _session: Session,
      spaceId: string,
      nodeId: string,
      patch: { access?: string; enc?: boolean },
    ) => {
      const node = nodesBySpace.get(spaceId)?.get(nodeId)
      if (!node) return
      if (patch.access !== undefined) {
        if (patch.access === "space") delete node.access
        else node.access = patch.access
      }
      if (patch.enc !== undefined) {
        if (patch.enc) node.enc = true
        else delete node.enc
      }
    },
  )

  /** The isolated tier's ensure-the-node-keyring step. Records `spaceId:nodeId`
   *  so a test can assert it ran BEFORE the write that needs it. */
  const ensuredKeyrings: string[] = []
  const ensureNodeKeyring = vi.fn(async (_session: Session, spaceId: string, nodeId: string) => {
    ensuredKeyrings.push(`${spaceId}:${nodeId}`)
  })

  const port: SpacePort = {
    readSpaces: vi.fn(async () => ({ spaces: [...spacesByName.values()] })),
    createSpace,
    readObjectTree: vi.fn(async (_session, spaceId: string) => [...(nodesBySpace.get(spaceId)?.values() ?? [])]),
    createNode,
    setNodeAccess,
    ensureNodeKeyring,
    getNodeAccess: vi.fn(
      async (_spaceId: string, nodeId: string, node: { access?: string; enc?: boolean }) => {
        const handle: NodeAccessHandle = {
          encryptor: null,
          client: {} as never,
          isOwnerOpen: true,
          async push(pullPath, pushPath, mutator) {
            const cur = nodeContent.get(nodeId) ?? null
            const next = mutator(cur)
            pushes.push({
              nodeId,
              access: node?.access,
              enc: node?.enc,
              pullPath,
              pushPath,
              data: next as Record<string, unknown> | null,
            })
            if (next !== null) nodeContent.set(nodeId, next)
          },
        }
        return handle
      },
    ),
  }

  return {
    port,
    spacesByName,
    nodesBySpace,
    nodeContent,
    pushes,
    createSpace,
    createNode,
    setNodeAccess,
    ensureNodeKeyring,
    ensuredKeyrings,
  }
}

/**
 * Wrap a fake port so the CAS push for ONE collection's node throws — the
 * 413 / exhausted-CAS-409 / network-blip case, raised at the exact call the
 * real port would fail on rather than by faking `readSource`.
 */
function failPushForType(
  base: ReturnType<typeof makeFakePort>,
  type: string,
  message: string,
): SpacePort {
  return {
    ...base.port,
    getNodeAccess: async (spaceId, nodeId, node, session) => {
      const handle = await base.port.getNodeAccess(spaceId, nodeId, node, session)
      const target = [...(base.nodesBySpace.get(spaceId)?.values() ?? [])].find(
        (n) => n.id === nodeId,
      )
      if (target?.type !== type) return handle
      return {
        ...handle,
        push: async () => {
          throw new Error(message)
        },
      }
    },
  }
}

/** What the channel creates a default (`"private"`) node with, and what a
 *  hand-seeded "this channel already created it in an earlier run" node must
 *  therefore carry. Seeding without them is a DIFFERENT node — a plaintext
 *  space node — and the channel is right to treat that as a flip. */
const PRIVATE_AXES = { access: "space", enc: true } as const
const PUBLIC_AXES = { access: "public", enc: false } as const

const FAKE_SESSION = { userId: "u1" } as unknown as Session
const docPath = (_collectionId: string, spaceId: string, nodeId: string) =>
  `spaces/${spaceId}/objects/mirror/${nodeId}`

function storedNodeFor(
  nodesBySpace: Map<string, Map<string, FakeNode>>,
  spaceId: string,
  type: string,
): FakeNode {
  const node = [...(nodesBySpace.get(spaceId)?.values() ?? [])].find((n) => n.type === type)
  if (!node) throw new Error(`no node of type "${type}" in space "${spaceId}"`)
  return node
}

function nodeIdFor(nodesBySpace: Map<string, Map<string, FakeNode>>, spaceId: string, type: string): string {
  return storedNodeFor(nodesBySpace, spaceId, type).id
}

describe("createSpaceMirrorChannel", () => {
  it("create-on-first-sync: creates a node, writes it, and reports it", async () => {
    const { port, nodesBySpace, nodeContent } = makeFakePort()
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [{ id: "a", spaceName: "sp1" }],
      enabledIds: () => ["a"],
      readSource: async (id) => ({ v: id }),
      docPath,
      port,
    })

    await channel.sync(REPLICATOR_CTX)

    expect(channel.result.created).toEqual(["a"])
    expect(channel.result.written).toEqual(["a"])
    expect(channel.result.cleared).toEqual([])
    expect(channel.result.failed).toEqual([])
    const spaceId = channel.result.spaces["sp1"]
    expect(spaceId).toBeTruthy()
    const nodeId = nodeIdFor(nodesBySpace, spaceId!, "a")
    expect(nodeContent.get(nodeId)).toEqual({ v: "a" })
  })

  it("reuse-existing-node: an already-present node is written, never re-created", async () => {
    const { port, createSpace, createNode } = makeFakePort()
    // Pre-seed: the space + node already exist before this channel ever runs.
    const space = await createSpace(FAKE_SESSION, "sp1")
    await createNode(FAKE_SESSION, space.id, { type: "a", title: "a", ...PRIVATE_AXES })
    createNode.mockClear()

    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [{ id: "a", spaceName: "sp1" }],
      enabledIds: () => ["a"],
      readSource: async () => ({ v: 2 }),
      docPath,
      port,
    })

    await channel.sync(REPLICATOR_CTX)

    expect(createNode).not.toHaveBeenCalled()
    expect(channel.result.created).toEqual([])
    expect(channel.result.written).toEqual(["a"])
  })

  it("clear-on-disable: disabling a collection clears its node content but keeps the node", async () => {
    const { port, createSpace, createNode, nodeContent } = makeFakePort()
    const space = await createSpace(FAKE_SESSION, "sp1")
    const node = await createNode(FAKE_SESSION, space.id, { type: "a", title: "a", ...PRIVATE_AXES })
    nodeContent.set(node.id, { v: "old" })

    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [{ id: "a", spaceName: "sp1" }],
      enabledIds: () => [], // disabled
      readSource: async () => {
        throw new Error("readSource must not be called for a disabled collection")
      },
      docPath,
      port,
    })

    await channel.sync(REPLICATOR_CTX)

    expect(channel.result.cleared).toEqual(["a"])
    expect(channel.result.written).toEqual([])
    expect(nodeContent.get(node.id)).toEqual({})
  })

  it("clear-on-disable: a reused channel instance does not re-clear an already-cleared node on the next cycle", async () => {
    const { port, createSpace, createNode } = makeFakePort()
    const space = await createSpace(FAKE_SESSION, "sp1")
    await createNode(FAKE_SESSION, space.id, { type: "a", title: "a", ...PRIVATE_AXES })

    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [{ id: "a", spaceName: "sp1" }],
      enabledIds: () => [], // disabled from the start
      readSource: async () => ({}),
      docPath,
      port,
    })

    await channel.sync(REPLICATOR_CTX)
    expect(channel.result.cleared).toEqual(["a"])
    const getNodeAccessCallsAfterFirst = vi.mocked(port.getNodeAccess).mock.calls.length

    // Same channel instance, same (still-disabled) state, next cycle.
    await channel.sync(REPLICATOR_CTX)
    expect(channel.result.cleared).toEqual(["a"]) // still reported as "clear-eligible"...
    // ...but no new CAS write happened for it the second time.
    expect(vi.mocked(port.getNodeAccess).mock.calls.length).toBe(getNodeAccessCallsAfterFirst)
  })

  it("clear-on-disable: re-enabling then disabling again clears for real, not skipped", async () => {
    const { port, createSpace, createNode, nodeContent } = makeFakePort()
    const space = await createSpace(FAKE_SESSION, "sp1")
    const node = await createNode(FAKE_SESSION, space.id, { type: "a", title: "a", ...PRIVATE_AXES })

    let enabled = false
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [{ id: "a", spaceName: "sp1" }],
      enabledIds: () => (enabled ? ["a"] : []),
      readSource: async () => ({ v: "fresh" }),
      docPath,
      port,
    })

    await channel.sync(REPLICATOR_CTX) // disabled -> cleared
    expect(channel.result.cleared).toEqual(["a"])

    enabled = true
    await channel.sync(REPLICATOR_CTX) // re-enabled -> written
    expect(channel.result.written).toEqual(["a"])
    expect(nodeContent.get(node.id)).toEqual({ v: "fresh" })

    enabled = false
    await channel.sync(REPLICATOR_CTX) // disabled again -> must actually clear, not skip
    expect(channel.result.cleared).toEqual(["a"])
    expect(nodeContent.get(node.id)).toEqual({})
  })

  it("two-space routing: collections routed to different spaceNames land in independent spaces", async () => {
    const { port, nodesBySpace } = makeFakePort()
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [
        { id: "a", spaceName: "shared" },
        { id: "b", spaceName: "private" },
      ],
      enabledIds: () => ["a", "b"],
      readSource: async (id) => ({ v: id }),
      docPath,
      port,
    })

    await channel.sync(REPLICATOR_CTX)

    const sharedId = channel.result.spaces["shared"]!
    const privateId = channel.result.spaces["private"]!
    expect(sharedId).toBeTruthy()
    expect(privateId).toBeTruthy()
    expect(sharedId).not.toBe(privateId)
    expect(nodesBySpace.get(sharedId)!.size).toBe(1)
    expect(nodesBySpace.get(privateId)!.size).toBe(1)
    expect(channel.result.created.sort()).toEqual(["a", "b"])
  })

  it('changeDetection "source-hash": skips an unchanged write on an existing node, re-writes on change', async () => {
    const { port, createSpace, createNode, nodeContent } = makeFakePort()
    const space = await createSpace(FAKE_SESSION, "sp1")
    const node = await createNode(FAKE_SESSION, space.id, { type: "a", title: "a", ...PRIVATE_AXES })
    nodeContent.set(node.id, { v: 1 }) // pre-existing content, not written by this channel

    let value = 1
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [{ id: "a", spaceName: "sp1" }],
      enabledIds: () => ["a"],
      readSource: async () => ({ v: value }),
      docPath,
      changeDetection: "source-hash",
      port,
    })

    // First sync: node pre-existed but this channel has no recorded hash for
    // it yet, so it writes (and records the hash).
    await channel.sync(REPLICATOR_CTX)
    expect(channel.result.written).toEqual(["a"])
    expect(channel.result.skipped).toEqual([])

    // Second sync, unchanged source data: skipped.
    await channel.sync(REPLICATOR_CTX)
    expect(channel.result.written).toEqual([])
    expect(channel.result.skipped).toEqual(["a"])

    // Third sync, source data changed: writes again.
    value = 2
    await channel.sync(REPLICATOR_CTX)
    expect(channel.result.written).toEqual(["a"])
    expect(channel.result.skipped).toEqual([])
    expect(nodeContent.get(node.id)).toEqual({ v: 2 })
  })

  it("changeDetection default (none) always writes, matching the original hand-rolled writer", async () => {
    const { port } = makeFakePort()
    const readSource = vi.fn(async () => ({ v: 1 }))
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [{ id: "a", spaceName: "sp1" }],
      enabledIds: () => ["a"],
      readSource,
      docPath,
      port,
    })

    await channel.sync(REPLICATOR_CTX)
    await channel.sync(REPLICATOR_CTX)

    expect(channel.result.written).toEqual(["a"])
    expect(channel.result.skipped).toEqual([])
    expect(readSource).toHaveBeenCalledTimes(2)
  })

  it("passes the caller's ReplicaCallContext through to readSource unchanged", async () => {
    const { port } = makeFakePort()
    const seen: ReplicaCallContext[] = []
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [{ id: "a", spaceName: "sp1" }],
      enabledIds: () => ["a"],
      readSource: async (_id, ctx) => {
        seen.push(ctx)
        return {}
      },
      docPath,
      port,
    })

    await channel.sync(REPLICATOR_CTX)
    expect(seen[0]!.callKind).toBe("replicator")

    await channel.sync({ callKind: "classic" })
    expect(seen[1]!.callKind).toBe("classic")
  })

  it("skips creating an empty space when nothing is enabled and it never existed", async () => {
    const { port, createSpace } = makeFakePort()
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [{ id: "a", spaceName: "sp1" }],
      enabledIds: () => [],
      readSource: async () => ({}),
      docPath,
      port,
    })

    await channel.sync(REPLICATOR_CTX)

    expect(createSpace).not.toHaveBeenCalled()
    expect(channel.result.spaces["sp1"]).toBeNull()
  })

  it("failure isolation: one collection's failing write still lets the others in the same space write", async () => {
    const fake = makeFakePort()
    const { nodesBySpace, nodeContent } = fake
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [
        { id: "a", spaceName: "sp1" },
        { id: "b", spaceName: "sp1" },
        { id: "c", spaceName: "sp1" },
      ],
      enabledIds: () => ["a", "b", "c"],
      readSource: async (id) => ({ v: id }),
      docPath,
      port: failPushForType(fake, "b", "413 payload too large"),
    })

    // The failure is reported, not swallowed — but only AFTER the cycle ran.
    await expect(channel.sync(REPLICATOR_CTX)).rejects.toThrow(/413 payload too large|failed to sync/)

    expect(channel.result.failed).toEqual(["b"])
    expect(channel.result.written).toEqual(["a", "c"])
    const spaceId = channel.result.spaces["sp1"]!
    expect(nodeContent.get(nodeIdFor(nodesBySpace, spaceId, "a"))).toEqual({ v: "a" })
    expect(nodeContent.get(nodeIdFor(nodesBySpace, spaceId, "c"))).toEqual({ v: "c" })
    expect(nodeContent.get(nodeIdFor(nodesBySpace, spaceId, "b"))).toBeUndefined()
  })

  it("failure isolation: a collection whose node create throws is not reported as created", async () => {
    // `created` used to come straight from `plan.toCreate` — what SHOULD be
    // created, not what was. A create that threw therefore put the same id in
    // both `created` and `failed`, and a caller reconciling the two could not
    // tell whether the node exists.
    const fake = makeFakePort()
    const port: SpacePort = {
      ...fake.port,
      createNode: async (session, spaceId, input) => {
        if ((input as { type: string }).type === "b") throw new Error("node create rejected")
        return fake.port.createNode(session, spaceId, input)
      },
    }
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [
        { id: "a", spaceName: "sp1" },
        { id: "b", spaceName: "sp1" },
      ],
      enabledIds: () => ["a", "b"],
      readSource: async (id) => ({ v: id }),
      docPath,
      port,
    })

    await expect(channel.sync(REPLICATOR_CTX)).rejects.toThrow(
      /node create rejected|failed to sync/,
    )

    expect(channel.result.failed).toEqual(["b"])
    expect(channel.result.created).toEqual(["a"]) // NOT ["a", "b"]
    expect(channel.result.written).toEqual(["a"])
  })

  it("failure isolation: one space failing leaves the other space's results intact", async () => {
    const fake = makeFakePort()
    const { nodesBySpace, nodeContent } = fake
    const port: SpacePort = {
      ...fake.port,
      createSpace: async (session, name) => {
        if (name === "bad") throw new Error("space registry unreachable")
        return fake.port.createSpace(session, name)
      },
    }

    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [
        { id: "a", spaceName: "good" },
        { id: "b", spaceName: "bad" },
      ],
      enabledIds: () => ["a", "b"],
      readSource: async (id) => ({ v: id }),
      docPath,
      port,
    })

    await expect(channel.sync(REPLICATOR_CTX)).rejects.toThrow(/space registry unreachable|failed to sync/)

    expect(channel.result.failed).toEqual(["b"])
    expect(channel.result.written).toEqual(["a"])
    expect(channel.result.spaces["bad"]).toBeNull()
    const goodId = channel.result.spaces["good"]!
    expect(goodId).toBeTruthy()
    expect(nodeContent.get(nodeIdFor(nodesBySpace, goodId, "a"))).toEqual({ v: "a" })
  })

  it("failure isolation: a failing clear does not cost the other collections their write", async () => {
    const fake = makeFakePort()
    const { nodeContent, createSpace, createNode } = fake
    const space = await createSpace(FAKE_SESSION, "sp1")
    const staleNode = await createNode(FAKE_SESSION, space.id, { type: "a", title: "a", ...PRIVATE_AXES })
    nodeContent.set(staleNode.id, { v: "stale" })

    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [
        { id: "a", spaceName: "sp1" }, // disabled -> to clear, and its push fails
        { id: "b", spaceName: "sp1" },
      ],
      enabledIds: () => ["b"],
      readSource: async (id) => ({ v: id }),
      docPath,
      port: failPushForType(fake, "a", "network reset while clearing"),
    })

    await expect(channel.sync(REPLICATOR_CTX)).rejects.toThrow(
      /network reset while clearing|failed to sync/,
    )

    expect(channel.result.failed).toEqual(["a"])
    expect(channel.result.cleared).toEqual([]) // never claim a clear that threw
    expect(channel.result.written).toEqual(["b"])
    expect(nodeContent.get(staleNode.id)).toEqual({ v: "stale" }) // untouched, as expected
  })

  it("failure isolation: `result` is replaced, not left stale, after a cycle that failed", async () => {
    const fake = makeFakePort()
    let breakTree = false
    const port: SpacePort = {
      ...fake.port,
      readObjectTree: async (session, spaceId) => {
        if (breakTree) throw new Error("object tree unreachable")
        return fake.port.readObjectTree(session, spaceId)
      },
    }

    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [
        { id: "a", spaceName: "sp1" },
        { id: "b", spaceName: "sp1" },
      ],
      enabledIds: () => ["a", "b"],
      readSource: async (id) => ({ v: id }),
      docPath,
      port,
    })

    await channel.sync(REPLICATOR_CTX)
    expect(channel.result.written).toEqual(["a", "b"])
    const goodSpaceId = channel.result.spaces["sp1"]
    expect(goodSpaceId).toBeTruthy()

    breakTree = true
    await expect(channel.sync(REPLICATOR_CTX)).rejects.toThrow(
      /object tree unreachable|failed to sync/,
    )

    // Not the previous cycle's numbers: nothing was written this time.
    expect(channel.result.written).toEqual([])
    expect(channel.result.failed).toEqual(["a", "b"])
    expect(channel.result.spaces["sp1"]).toBeNull()
  })

  it('tier: a "public" collection is created and written world-readable while a "private" one in the SAME space stays space-gated + encrypted', async () => {
    const { port, nodesBySpace, pushes, createNode } = makeFakePort()
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [
        { id: "pub", spaceName: "sp1", tier: "public" },
        { id: "priv", spaceName: "sp1", tier: "private" },
        { id: "untiered", spaceName: "sp1" },
      ],
      enabledIds: () => ["pub", "priv", "untiered"],
      readSource: async (id) => ({ v: id }),
      docPath,
      port,
    })

    await channel.sync(REPLICATOR_CTX)

    // Born under the right access mode — a public node created space-gated
    // would publish nothing readable at its URL.
    const createArgs = createNode.mock.calls.map(([, , input]) => input as Record<string, unknown>)
    expect(createArgs.find((i) => i["type"] === "pub")).toMatchObject({
      access: "public",
      enc: false,
    })
    expect(createArgs.find((i) => i["type"] === "priv")).toMatchObject({
      access: "space",
      enc: true,
    })
    // No `tier` at all: unchanged from before tiers existed — the channel-wide
    // `nodeEnc` default.
    expect(createArgs.find((i) => i["type"] === "untiered")).toMatchObject({
      access: "space",
      enc: true,
    })

    // ...and the WRITE goes out under the same per-collection mode, not the
    // channel-wide default.
    const spaceId = channel.result.spaces["sp1"]!
    const pubNode = nodeIdFor(nodesBySpace, spaceId, "pub")
    const privNode = nodeIdFor(nodesBySpace, spaceId, "priv")
    expect(pushes.find((p) => p.nodeId === pubNode)).toMatchObject({
      access: "public",
      enc: false,
    })
    expect(pushes.find((p) => p.nodeId === privNode)).toMatchObject({
      access: "space",
      enc: true,
    })
    expect(channel.result.written.sort()).toEqual(["priv", "pub", "untiered"])
  })

  it("docPath receives the collection id, on the write path AND the clear path", async () => {
    const { port, createSpace, createNode } = makeFakePort()
    const space = await createSpace(FAKE_SESSION, "sp1")
    await createNode(FAKE_SESSION, space.id, { type: "stale", title: "stale", ...PRIVATE_AXES })

    const seen: string[][] = []
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [
        { id: "a", spaceName: "sp1" },
        { id: "stale", spaceName: "sp1" },
      ],
      enabledIds: () => ["a"], // "stale" is disabled -> clear path
      readSource: async () => ({}),
      docPath: (collectionId, spaceId, nodeId) => {
        seen.push([collectionId, spaceId, nodeId])
        return `spaces/${spaceId}/objects/${collectionId}/${nodeId}`
      },
      port,
    })

    await channel.sync(REPLICATOR_CTX)

    expect(seen.map(([collectionId]) => collectionId).sort()).toEqual([
      "a",
      "a",
      "stale",
      "stale",
    ]) // pull + push path, for the write and for the clear
    // The id really reaches the built path, not just the callback.
    const spaceId = channel.result.spaces["sp1"]!
    const forStale = seen.find(([collectionId]) => collectionId === "stale")!
    expect(forStale[1]).toBe(spaceId)
  })

  it("title: a caller-supplied title reaches createNode, and the default is the collection id", async () => {
    const withTitle = makeFakePort()
    const titled = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [{ id: "user-accounts", spaceName: "sp1" }],
      enabledIds: () => ["user-accounts"],
      readSource: async () => ({}),
      docPath,
      title: (collectionId) => `Mirror: ${collectionId}`,
      port: withTitle.port,
    })
    await titled.sync(REPLICATOR_CTX)
    expect(withTitle.createNode.mock.calls[0]![2]).toMatchObject({
      type: "user-accounts",
      title: "Mirror: user-accounts",
    })

    const noTitle = makeFakePort()
    const untitled = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [{ id: "user-accounts", spaceName: "sp1" }],
      enabledIds: () => ["user-accounts"],
      readSource: async () => ({}),
      docPath,
      port: noTitle.port,
    })
    await untitled.sync(REPLICATOR_CTX)
    expect(noTitle.createNode.mock.calls[0]![2]).toMatchObject({
      type: "user-accounts",
      title: "user-accounts",
    })
  })

  it("tier flip: private -> public clears the OLD tier's copy before writing the new one, and source-hash does not skip the migrating write", async () => {
    const { port, nodesBySpace, pushes } = makeFakePort()
    // Live registry entry — the caller flips this collection's tier between
    // cycles, exactly like a settings toggle would, without rebuilding the
    // channel.
    const collections: SpaceMirrorCollection[] = [
      { id: "a", spaceName: "sp1", tier: "private" },
    ]
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections,
      enabledIds: () => ["a"],
      // Byte-identical every cycle: a tier flip does NOT change what the
      // source returns, which is precisely why a node-id-keyed source hash
      // would skip the one write that migrates the node.
      readSource: async () => ({ v: "constant" }),
      docPath,
      changeDetection: "source-hash",
      port,
    })

    await channel.sync(REPLICATOR_CTX) // creates + writes private
    expect(channel.result.written).toEqual(["a"])
    await channel.sync(REPLICATOR_CTX) // unchanged, same tier -> legitimately skipped
    expect(channel.result.skipped).toEqual(["a"])

    const spaceId = channel.result.spaces["sp1"]!
    const nodeId = nodeIdFor(nodesBySpace, spaceId, "a")
    pushes.length = 0

    collections[0]!.tier = "public"
    await channel.sync(REPLICATOR_CTX)

    // Not skipped, even though the source bytes are identical.
    expect(channel.result.written).toEqual(["a"])
    expect(channel.result.skipped).toEqual([])

    // Exactly two pushes, in this order: the old (private) copy emptied, THEN
    // the new public content written. The reverse order — or no clear at all —
    // is what leaves plaintext at a world-readable URL on the way back down.
    expect(pushes).toHaveLength(2)
    expect(pushes[0]).toMatchObject({
      nodeId,
      access: "space",
      enc: true,
      data: {},
    })
    expect(pushes[1]).toMatchObject({
      nodeId,
      access: "public",
      enc: false,
      data: { v: "constant" },
    })
  })

  it("public clear is never skipped, even on a reused channel instance that already cleared it", async () => {
    const { port, createSpace, createNode, pushes } = makeFakePort()
    const space = await createSpace(FAKE_SESSION, "sp1")
    await createNode(FAKE_SESSION, space.id, { type: "pub", title: "pub", ...PUBLIC_AXES })
    await createNode(FAKE_SESSION, space.id, { type: "priv", title: "priv", ...PRIVATE_AXES })

    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [
        { id: "pub", spaceName: "sp1", tier: "public" },
        { id: "priv", spaceName: "sp1", tier: "private" },
      ],
      enabledIds: () => [], // both disabled from the start
      readSource: async () => ({}),
      docPath,
      port,
    })

    await channel.sync(REPLICATOR_CTX)
    expect(channel.result.cleared.sort()).toEqual(["priv", "pub"])
    expect(pushes).toHaveLength(2)
    pushes.length = 0

    // Same instance, same still-disabled state, next cycle. The private node
    // takes the already-cleared short-circuit; the public one must NOT — a
    // missed clear there leaves world-readable data, which is not symmetric
    // with leaving stale ciphertext readable only by space members.
    await channel.sync(REPLICATOR_CTX)
    expect(channel.result.cleared.sort()).toEqual(["priv", "pub"])
    expect(pushes).toHaveLength(1)
    expect(pushes[0]).toMatchObject({ access: "public", enc: false, data: {} })
  })

  it('tier: an explicit "private" resolves to a custom nodeEnc, exactly like omitting tier', async () => {
    // `tier` DEFAULTS to "private", so spelling it out and leaving it off have
    // to be the same thing. Resolving an explicit "private" to a hardcoded
    // `{ access: "space", enc: true }` silently threw away a caller's
    // `nodeEnc` override — and only for the collections that documented their
    // tier, which is the opposite of what writing it down should do.
    const { port, nodesBySpace, pushes, createNode } = makeFakePort()
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [
        { id: "explicit", spaceName: "sp1", tier: "private" },
        { id: "omitted", spaceName: "sp1" },
        { id: "pub", spaceName: "sp1", tier: "public" },
      ],
      enabledIds: () => ["explicit", "omitted", "pub"],
      readSource: async (id) => ({ v: id }),
      docPath,
      // Deliberately NOT { access: "invite", enc: true }: that pair is the
      // isolated tier's, and is routed through the per-node keyring wherever
      // it appears. This is just "some non-default private variant".
      nodeEnc: { access: "owner", enc: true },
      port,
    })

    await channel.sync(REPLICATOR_CTX)

    const createArgs = createNode.mock.calls.map(([, , input]) => input as Record<string, unknown>)
    const createdAxes = (type: string) => {
      const input = createArgs.find((a) => a["type"] === type)!
      return { access: input["access"], enc: input["enc"] }
    }
    expect(createdAxes("explicit")).toEqual({ access: "owner", enc: true })
    expect(createdAxes("explicit")).toEqual(createdAxes("omitted"))
    // "public" is the ONE tier that overrides `nodeEnc` — it has to, since
    // `access:"public"` with `enc:true` is what the server refuses.
    expect(createdAxes("pub")).toEqual({ access: "public", enc: false })

    // Same on the write path, not just at create.
    const spaceId = channel.result.spaces["sp1"]!
    const pushedAxes = (type: string) => {
      const push = pushes.find((p) => p.nodeId === nodeIdFor(nodesBySpace, spaceId, type))!
      return { access: push.access, enc: push.enc }
    }
    expect(pushedAxes("explicit")).toEqual({ access: "owner", enc: true })
    expect(pushedAxes("explicit")).toEqual(pushedAxes("omitted"))
    expect(pushedAxes("pub")).toEqual({ access: "public", enc: false })
  })

  it("tier flip across a restart: a FRESH channel detects public -> private from the node's STORED axes and clears the old public path", async () => {
    // The flip that actually matters. A user toggles a collection off "public"
    // in settings and the app restarts (or the caller builds a channel per
    // call): the new instance has no memory of ever writing this node, so a
    // flip detected from in-memory state finds nothing, skips the clear, and
    // leaves the published plaintext readable at its world-readable URL
    // indefinitely. The node's STORED axes still say "public", and they are
    // what drives the clear here.
    const { port, nodesBySpace, pushes } = makeFakePort()
    const shared = {
      name: "mirror",
      session: FAKE_SESSION,
      enabledIds: () => ["a"],
      readSource: async () => ({ v: "published" }),
      docPath,
      port,
    }

    const beforeRestart = createSpaceMirrorChannel({
      ...shared,
      collections: [{ id: "a", spaceName: "sp1", tier: "public" }],
    })
    await beforeRestart.sync(REPLICATOR_CTX)
    const spaceId = beforeRestart.result.spaces["sp1"]!
    const nodeId = nodeIdFor(nodesBySpace, spaceId, "a")
    pushes.length = 0

    const afterRestart = createSpaceMirrorChannel({
      ...shared,
      collections: [{ id: "a", spaceName: "sp1", tier: "private" }],
    })
    await afterRestart.sync(REPLICATOR_CTX)

    expect(afterRestart.result.created).toEqual([]) // the same node, reused
    expect(afterRestart.result.written).toEqual(["a"])
    // Old public copy emptied FIRST, under the public axes that actually reach
    // it, then the private content written.
    expect(pushes).toHaveLength(2)
    expect(pushes[0]).toMatchObject({ nodeId, access: "public", enc: false, data: {} })
    expect(pushes[1]).toMatchObject({
      nodeId,
      access: "space",
      enc: true,
      data: { v: "published" },
    })
  })

  it("stored axes: a node recorded with NEITHER access nor enc reads as space/plaintext, not as a flip", async () => {
    // The object index omits `access` when it is "space" and `enc` when false,
    // so a plaintext space node is stored with both fields simply absent.
    // Reading that back as "unknown" rather than "the defaults" would make
    // every such node look permanently flipped and re-clear it every cycle.
    const { port, createSpace, createNode, pushes } = makeFakePort()
    const space = await createSpace(FAKE_SESSION, "sp1")
    const node = await createNode(FAKE_SESSION, space.id, {
      type: "a",
      title: "a",
      access: "space",
      enc: false,
    })
    expect(node.access).toBeUndefined()
    expect(node.enc).toBeUndefined()

    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [{ id: "a", spaceName: "sp1", tier: "private" }],
      enabledIds: () => ["a"],
      readSource: async (id) => ({ v: id }),
      docPath,
      nodeEnc: { enc: false },
      port,
    })

    await channel.sync(REPLICATOR_CTX)

    // Exactly one push — the write. A misread would have prepended a clear.
    expect(pushes).toHaveLength(1)
    expect(pushes[0]).toMatchObject({ access: "space", enc: false, data: { v: "a" } })
  })

  it("tier flip public -> private: the node's STORED axes are patched to private, so the public index projection no longer sees it", async () => {
    // The reason this matters is not bookkeeping. Infra's public-objects
    // projection extracts every node whose STORED `access` is "public" out of
    // an objindex write and upserts { id, title, type, updatedAt } into a
    // world-readable index keyed by spaceId. Clearing the CONTENT on the flip
    // (which the channel already did) leaves that entry standing: the node
    // keeps advertising its id, title and type to anonymous callers forever,
    // directly contradicting the setting the user just changed.
    const { port, nodesBySpace } = makeFakePort()
    const shared = {
      name: "mirror",
      session: FAKE_SESSION,
      enabledIds: () => ["a"],
      readSource: async () => ({ v: "published" }),
      docPath,
      port,
    }

    const asPublic = createSpaceMirrorChannel({
      ...shared,
      collections: [{ id: "a", spaceName: "sp1", tier: "public" }],
    })
    await asPublic.sync(REPLICATOR_CTX)
    const spaceId = asPublic.result.spaces["sp1"]!
    expect(storedNodeFor(nodesBySpace, spaceId, "a")).toMatchObject({ access: "public" })

    const asPrivate = createSpaceMirrorChannel({
      ...shared,
      collections: [{ id: "a", spaceName: "sp1", tier: "private" }],
    })
    await asPrivate.sync(REPLICATOR_CTX)

    // Indistinguishable from a node BORN private: the index omits `access`
    // when it is "space", so the projection's `access === "public"` filter
    // cannot match it any more.
    const stored = storedNodeFor(nodesBySpace, spaceId, "a")
    expect(stored.access).toBeUndefined()
    expect(stored.enc).toBe(true)
  })

  it("tier flip private -> public: the node's STORED axes are patched to public", async () => {
    const { port, nodesBySpace } = makeFakePort()
    const collections: SpaceMirrorCollection[] = [{ id: "a", spaceName: "sp1", tier: "private" }]
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections,
      enabledIds: () => ["a"],
      readSource: async () => ({ v: "constant" }),
      docPath,
      port,
    })

    await channel.sync(REPLICATOR_CTX)
    const spaceId = channel.result.spaces["sp1"]!
    expect(storedNodeFor(nodesBySpace, spaceId, "a").access).toBeUndefined()

    collections[0]!.tier = "public"
    await channel.sync(REPLICATOR_CTX)

    const stored = storedNodeFor(nodesBySpace, spaceId, "a")
    expect(stored.access).toBe("public")
    // `enc` DROPPED, not stored as false — the same normalization `createNode`
    // applies, so this node is indistinguishable from one born public.
    expect(stored.enc).toBeUndefined()
  })

  it("a tier flip is self-limiting: the next cycle with the SAME configuration performs no clear and no second patch", async () => {
    // Without the stored-axes patch the object index records the OLD tier
    // forever, so every subsequent cycle re-detects the same flip and re-fires
    // the clear — unbounded, for the life of the collection. The push count is
    // the observable: a flipping cycle pushes twice (clear + write), a settled
    // one pushes once.
    const { port, nodesBySpace, pushes, setNodeAccess } = makeFakePort()
    const collections: SpaceMirrorCollection[] = [{ id: "a", spaceName: "sp1", tier: "private" }]
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections,
      enabledIds: () => ["a"],
      readSource: async () => ({ v: "constant" }),
      docPath,
      port,
    })

    await channel.sync(REPLICATOR_CTX)
    collections[0]!.tier = "public"
    pushes.length = 0

    await channel.sync(REPLICATOR_CTX) // the flip: clear + write + patch
    expect(pushes).toHaveLength(2)
    expect(setNodeAccess).toHaveBeenCalledTimes(1)
    const spaceId = channel.result.spaces["sp1"]!
    const nodeId = nodeIdFor(nodesBySpace, spaceId, "a")
    expect(setNodeAccess).toHaveBeenCalledWith(FAKE_SESSION, spaceId, nodeId, {
      access: "public",
      enc: false,
    })
    pushes.length = 0

    await channel.sync(REPLICATOR_CTX) // settled: write only
    expect(pushes).toHaveLength(1)
    expect(pushes[0]).toMatchObject({ access: "public", enc: false, data: { v: "constant" } })
    expect(setNodeAccess).toHaveBeenCalledTimes(1)
  })

  it("source-hash: a collection that flipped once can skip a later unchanged cycle", async () => {
    // Impossible before the stored-axes patch: the flip re-fired every cycle,
    // and its clear dropped the node's fingerprints each time, so a flipped
    // collection could never skip again no matter how unchanged its source was.
    const { port, pushes } = makeFakePort()
    const collections: SpaceMirrorCollection[] = [{ id: "a", spaceName: "sp1", tier: "private" }]
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections,
      enabledIds: () => ["a"],
      readSource: async () => ({ v: "constant" }),
      docPath,
      changeDetection: "source-hash",
      port,
    })

    await channel.sync(REPLICATOR_CTX)
    collections[0]!.tier = "public"
    await channel.sync(REPLICATOR_CTX) // the migrating write, never skipped
    expect(channel.result.written).toEqual(["a"])
    pushes.length = 0

    await channel.sync(REPLICATOR_CTX)

    expect(channel.result.skipped).toEqual(["a"])
    expect(channel.result.written).toEqual([])
    expect(pushes).toHaveLength(0)
  })

  it("a failing setNodeAccess is isolated: only that collection fails, the others still wrote, and the error is in the group", async () => {
    const fake = makeFakePort()
    const boom = new Error("index CAS 409")
    const port: SpacePort = {
      ...fake.port,
      setNodeAccess: async (session, spaceId, nodeId, patch) => {
        const target = [...(fake.nodesBySpace.get(spaceId)?.values() ?? [])].find(
          (n) => n.id === nodeId,
        )
        if (target?.type === "a") throw boom
        return fake.port.setNodeAccess(session, spaceId, nodeId, patch)
      },
    }
    const collections: SpaceMirrorCollection[] = [
      { id: "a", spaceName: "sp1", tier: "private" },
      { id: "b", spaceName: "sp1", tier: "private" },
    ]
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections,
      enabledIds: () => ["a", "b"],
      readSource: async (id) => ({ v: id }),
      docPath,
      port,
    })

    await channel.sync(REPLICATOR_CTX)
    // Only "a" flips; "b" stays private, so its patch is never attempted.
    collections[0]!.tier = "public"

    await expect(channel.sync(REPLICATOR_CTX)).rejects.toThrow(AggregateError)
    expect(channel.result.failed).toEqual(["a"])
    expect(channel.result.written).toEqual(["b"])

    // The raised group carries the real error, not a stringified id.
    const err = await channel.sync(REPLICATOR_CTX).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(AggregateError)
    expect((err as AggregateError).errors).toContain(boom)
  })

  // ── The isolated tier ──────────────────────────────────────────────────────

  const isolatedChannel = (port: SpacePort, enabled: string[] = ["accounts"]) =>
    createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [{ id: "accounts", spaceName: "sp1", tier: "isolated" }],
      enabledIds: () => enabled,
      readSource: async (id) => ({ v: id }),
      docPath,
      port,
    })

  it("isolated: the node is created invite+enc", async () => {
    const fake = makeFakePort()
    await isolatedChannel(fake.port).sync(REPLICATOR_CTX)

    const input = fake.createNode.mock.calls[0]![2] as Record<string, unknown>
    expect({ access: input["access"], enc: input["enc"] }).toEqual({
      access: "invite",
      enc: true,
    })
  })

  it("isolated: ignores a channel-wide nodeEnc, like public does", async () => {
    const fake = makeFakePort()
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [{ id: "accounts", spaceName: "sp1", tier: "isolated" }],
      enabledIds: () => ["accounts"],
      readSource: async (id) => ({ v: id }),
      docPath,
      nodeEnc: { access: "owner", enc: true },
      port: fake.port,
    })

    await channel.sync(REPLICATOR_CTX)

    const input = fake.createNode.mock.calls[0]![2] as Record<string, unknown>
    expect(input["access"]).toBe("invite")
  })

  it("isolated: the per-node keyring is seeded before the write that needs it", async () => {
    // getNodeAccess opens the node keyring with the THROWING variant for
    // invite+enc — it never falls back to the space keyring, so an unseeded
    // keyring means the very first write fails rather than silently sealing
    // under the key every space member holds.
    const fake = makeFakePort()
    const channel = isolatedChannel(fake.port)

    await channel.sync(REPLICATOR_CTX)

    const spaceId = channel.result.spaces["sp1"]!
    const nodeId = nodeIdFor(fake.nodesBySpace, spaceId, "accounts")
    expect(fake.ensuredKeyrings).toEqual([`${spaceId}:${nodeId}`])
    // ...and the write really did go through the invite+enc axes.
    expect(fake.pushes.map((p) => ({ access: p.access, enc: p.enc }))).toEqual([
      { access: "invite", enc: true },
    ])
  })

  it("isolated: a clear also resolves through the node keyring", async () => {
    const fake = makeFakePort()
    const enabled = ["accounts"]
    const channel = isolatedChannel(fake.port, enabled)
    await channel.sync(REPLICATOR_CTX)
    const spaceId = channel.result.spaces["sp1"]!
    const nodeId = nodeIdFor(fake.nodesBySpace, spaceId, "accounts")

    enabled.length = 0
    await channel.sync(REPLICATOR_CTX)

    expect(channel.result.cleared).toEqual(["accounts"])
    expect(fake.nodeContent.get(nodeId)).toEqual({})
    expect(fake.ensuredKeyrings).toEqual([`${spaceId}:${nodeId}`, `${spaceId}:${nodeId}`])
  })

  it("isolated: a clear is never short-circuited by clearedNodes", async () => {
    // Same asymmetry as public: an isolated node is readable by every holder
    // of a still-valid per-node grant, so a wrongly skipped clear is not the
    // same cost as a wasted no-op push.
    const fake = makeFakePort()
    const enabled = ["accounts"]
    const channel = isolatedChannel(fake.port, enabled)
    await channel.sync(REPLICATOR_CTX)

    enabled.length = 0
    await channel.sync(REPLICATOR_CTX)
    const afterFirstClear = fake.pushes.length

    await channel.sync(REPLICATOR_CTX)

    expect(fake.pushes.length).toBe(afterFirstClear + 1)
  })

  it("isolated and private collections coexist in ONE space", async () => {
    // The point of the tier: one space per user, mixed sensitivities, and only
    // the isolated node is reachable by a per-node grant.
    const fake = makeFakePort()
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections: [
        { id: "accounts", spaceName: "sp1", tier: "isolated" },
        { id: "settings", spaceName: "sp1" },
      ],
      enabledIds: () => ["accounts", "settings"],
      readSource: async (id) => ({ v: id }),
      docPath,
      port: fake.port,
    })

    await channel.sync(REPLICATOR_CTX)

    const axesOf = (type: string) => {
      const input = fake.createNode.mock.calls
        .map(([, , i]) => i as Record<string, unknown>)
        .find((i) => i["type"] === type)!
      return input["access"]
    }
    expect(axesOf("accounts")).toBe("invite")
    expect(axesOf("settings")).toBe("space")
    expect(fake.createSpace).toHaveBeenCalledTimes(1)
    // Only the isolated node needed a per-node keyring.
    const spaceId = channel.result.spaces["sp1"]!
    expect(fake.ensuredKeyrings).toEqual([
      `${spaceId}:${nodeIdFor(fake.nodesBySpace, spaceId, "accounts")}`,
    ])
  })

  it("isolated -> private flip clears under the stored invite axes first", async () => {
    const fake = makeFakePort()
    const collections: SpaceMirrorCollection[] = [
      { id: "accounts", spaceName: "sp1", tier: "isolated" },
    ]
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections,
      enabledIds: () => ["accounts"],
      readSource: async (id) => ({ v: id }),
      docPath,
      port: fake.port,
    })
    await channel.sync(REPLICATOR_CTX)
    const spaceId = channel.result.spaces["sp1"]!
    const nodeId = nodeIdFor(fake.nodesBySpace, spaceId, "accounts")

    collections[0]!.tier = "private"
    await channel.sync(REPLICATOR_CTX)

    // clear under the OLD (invite) axes, then write under the new (space) ones
    const axes = fake.pushes.slice(1).map((p) => ({ access: p.access, enc: p.enc }))
    expect(axes).toEqual([
      { access: "invite", enc: true },
      { access: "space", enc: true },
    ])
    // stored axes patched, so the flip is self-limiting
    expect(fake.setNodeAccess).toHaveBeenCalledWith(FAKE_SESSION, spaceId, nodeId, {
      access: "space",
      enc: true,
    })
    expect(fake.nodesBySpace.get(spaceId)!.get(nodeId)!.access).toBeUndefined()
  })

  it("private -> isolated flip migrates onto the node keyring", async () => {
    const fake = makeFakePort()
    const collections: SpaceMirrorCollection[] = [{ id: "accounts", spaceName: "sp1" }]
    const channel = createSpaceMirrorChannel({
      name: "mirror",
      session: FAKE_SESSION,
      collections,
      enabledIds: () => ["accounts"],
      readSource: async (id) => ({ v: id }),
      docPath,
      port: fake.port,
    })
    await channel.sync(REPLICATOR_CTX)
    const spaceId = channel.result.spaces["sp1"]!
    const nodeId = nodeIdFor(fake.nodesBySpace, spaceId, "accounts")

    collections[0]!.tier = "isolated"
    await channel.sync(REPLICATOR_CTX)

    const axes = fake.pushes.slice(1).map((p) => ({ access: p.access, enc: p.enc }))
    expect(axes).toEqual([
      { access: "space", enc: true }, // clear under the stored (space) axes
      { access: "invite", enc: true }, // write under the node keyring
    ])
    expect(fake.ensuredKeyrings).toEqual([`${spaceId}:${nodeId}`])
    expect(fake.nodesBySpace.get(spaceId)!.get(nodeId)!.access).toBe("invite")
  })
})
