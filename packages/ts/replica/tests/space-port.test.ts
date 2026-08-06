/**
 * Regression test for `findOrCreateSpace`'s in-flight coalescing.
 *
 * Two concurrent callers racing on the same (session, name) before either
 * one's `readSpaces()` has resolved used to both see "not found" and both
 * call `createSpace`, producing two distinct spaces with the same name —
 * confirmed reachable once `cloudMirror.start()`'s periodic loop and an
 * interactive action (e.g. approving a website pairing) could overlap in the
 * same session. Concurrent calls must now coalesce into one actual
 * read+create.
 */
import { describe, expect, it, vi } from "vitest"
import { findOrCreateSpace } from "../src/space/port.js"
import type { Session, SpacePort } from "../src/space/port.js"

const FAKE_SESSION = { userId: "u1" } as unknown as Session

describe("findOrCreateSpace — concurrent-call coalescing", () => {
  it("two concurrent calls for the same (session, name) create only one space", async () => {
    let resolveRead!: () => void
    const readGate = new Promise<void>((resolve) => {
      resolveRead = resolve
    })
    const createSpace = vi.fn(async (_session: Session, name: string) => ({ id: "space-1", name }))
    const port: SpacePort = {
      readSpaces: vi.fn(async () => {
        await readGate
        return { spaces: [] }
      }),
      createSpace,
      readObjectTree: vi.fn(async () => []),
      createNode: vi.fn(),
      getNodeAccess: vi.fn(),
    }

    const call1 = findOrCreateSpace(FAKE_SESSION, "octobot-mirror", port)
    const call2 = findOrCreateSpace(FAKE_SESSION, "octobot-mirror", port)

    // Both calls are in flight, neither has resolved readSpaces yet.
    resolveRead()
    const [result1, result2] = await Promise.all([call1, call2])

    expect(createSpace).toHaveBeenCalledTimes(1)
    expect(result1).toEqual(result2)
    expect(result1).toEqual({ id: "space-1", name: "octobot-mirror" })
  })

  it("a call for a different name is not coalesced with an in-flight one", async () => {
    let resolveRead!: () => void
    const readGate = new Promise<void>((resolve) => {
      resolveRead = resolve
    })
    const createSpace = vi.fn(async (_session: Session, name: string) => ({ id: `id-${name}`, name }))
    const port: SpacePort = {
      readSpaces: vi.fn(async () => {
        await readGate
        return { spaces: [] }
      }),
      createSpace,
      readObjectTree: vi.fn(async () => []),
      createNode: vi.fn(),
      getNodeAccess: vi.fn(),
    }

    const shared = findOrCreateSpace(FAKE_SESSION, "octobot-mirror", port)
    const priv = findOrCreateSpace(FAKE_SESSION, "octobot-mirror-private", port)
    resolveRead()
    await Promise.all([shared, priv])

    expect(createSpace).toHaveBeenCalledTimes(2)
  })

  it("a later call after the first one resolved is not coalesced (re-reads fresh state)", async () => {
    const createSpace = vi.fn(async (_session: Session, name: string) => ({ id: "space-1", name }))
    const readSpaces = vi.fn(async () => ({ spaces: [{ id: "space-1", name: "octobot-mirror" }] }))
    const port: SpacePort = {
      readSpaces,
      createSpace,
      readObjectTree: vi.fn(async () => []),
      createNode: vi.fn(),
      getNodeAccess: vi.fn(),
    }

    await findOrCreateSpace(FAKE_SESSION, "octobot-mirror", port)
    await findOrCreateSpace(FAKE_SESSION, "octobot-mirror", port)

    expect(readSpaces).toHaveBeenCalledTimes(2)
    expect(createSpace).not.toHaveBeenCalled()
  })
})
