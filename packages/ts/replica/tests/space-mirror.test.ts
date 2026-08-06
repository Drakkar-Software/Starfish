/**
 * Tests for `createSpaceMirrorChannel` against a fake `SpacePort` — an
 * in-memory, path/id-keyed fake (no `vi.mock`), matching this monorepo's
 * fake-client idiom (see `packages/ts/sharing/tests/evict.test.ts`).
 */
import { describe, expect, it, vi } from "vitest"
import { createSpaceMirrorChannel } from "../src/space/mirror-channel.js"
import { REPLICATOR_CTX, type ReplicaCallContext } from "../src/channel.js"
import type { CreateNodeInput, NodeAccessHandle, Session, SpacePort } from "../src/space/port.js"

interface FakeNode {
  id: string
  type: string
}

function makeFakePort() {
  let spaceCounter = 0
  let nodeCounter = 0
  const spacesByName = new Map<string, { id: string; name: string }>()
  const nodesBySpace = new Map<string, Map<string, FakeNode>>()
  const nodeContent = new Map<string, Record<string, unknown>>()

  const createSpace = vi.fn(async (_session: Session, name: string) => {
    const id = `space-${++spaceCounter}`
    const space = { id, name }
    spacesByName.set(name, space)
    nodesBySpace.set(id, new Map())
    return space
  })

  const createNode = vi.fn(async (_session: Session, spaceId: string, input: CreateNodeInput) => {
    const id = `node-${++nodeCounter}`
    const node: FakeNode = { id, type: input.type }
    nodesBySpace.get(spaceId)!.set(id, node)
    return node
  })

  const port: SpacePort = {
    readSpaces: vi.fn(async () => ({ spaces: [...spacesByName.values()] })),
    createSpace,
    readObjectTree: vi.fn(async (_session, spaceId: string) => [...(nodesBySpace.get(spaceId)?.values() ?? [])]),
    createNode,
    getNodeAccess: vi.fn(async (_spaceId: string, nodeId: string) => {
      const handle: NodeAccessHandle = {
        encryptor: null,
        client: {} as never,
        isOwnerOpen: true,
        async push(_pullPath, _pushPath, mutator) {
          const cur = nodeContent.get(nodeId) ?? null
          const next = mutator(cur)
          if (next !== null) nodeContent.set(nodeId, next)
        },
      }
      return handle
    }),
  }

  return { port, spacesByName, nodesBySpace, nodeContent, createSpace, createNode }
}

const FAKE_SESSION = { userId: "u1" } as unknown as Session
const docPath = (spaceId: string, nodeId: string) => `spaces/${spaceId}/objects/mirror/${nodeId}`

function nodeIdFor(nodesBySpace: Map<string, Map<string, FakeNode>>, spaceId: string, type: string): string {
  const node = [...(nodesBySpace.get(spaceId)?.values() ?? [])].find((n) => n.type === type)
  if (!node) throw new Error(`no node of type "${type}" in space "${spaceId}"`)
  return node.id
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
    const spaceId = channel.result.spaces["sp1"]
    expect(spaceId).toBeTruthy()
    const nodeId = nodeIdFor(nodesBySpace, spaceId!, "a")
    expect(nodeContent.get(nodeId)).toEqual({ v: "a" })
  })

  it("reuse-existing-node: an already-present node is written, never re-created", async () => {
    const { port, createSpace, createNode } = makeFakePort()
    // Pre-seed: the space + node already exist before this channel ever runs.
    const space = await createSpace(FAKE_SESSION, "sp1")
    await createNode(FAKE_SESSION, space.id, { type: "a", title: "a" })
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
    const node = await createNode(FAKE_SESSION, space.id, { type: "a", title: "a" })
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
    await createNode(FAKE_SESSION, space.id, { type: "a", title: "a" })

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
    const node = await createNode(FAKE_SESSION, space.id, { type: "a", title: "a" })

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
    const node = await createNode(FAKE_SESSION, space.id, { type: "a", title: "a" })
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
})
