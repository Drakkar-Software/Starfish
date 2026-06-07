/**
 * mutateDoc — hash-CAS read-modify-write with conflict retry, 404-as-absent,
 * and no-op skipping.
 */
import { describe, it, expect } from "vitest"
import { mutateDoc } from "../src/mutate.js"
import { ConflictError, StarfishHttpError } from "../src/types.js"
import { createMockClient } from "../src/testing.js"

describe("mutateDoc", () => {
  it("pulls, mutates, and pushes with the read hash", async () => {
    const client = createMockClient({
      pull: async () => ({ data: { n: 1 }, hash: "h1", timestamp: 1 }),
    })
    const out = await mutateDoc<{ n: number }>(client, "/doc", (cur) => ({ n: (cur.data?.n ?? 0) + 1 }))
    expect(out).toEqual({ n: 2 })
    expect(client.pushCalls).toHaveLength(1)
    expect(client.pushCalls[0]!.baseHash).toBe("h1")
    expect(client.pushCalls[0]!.data).toEqual({ n: 2 })
  })

  it("retries on ConflictError against fresh state, then succeeds", async () => {
    let serverN = 10
    let serverHash = "h10"
    let pushes = 0
    const client = createMockClient({
      pull: async () => ({ data: { n: serverN }, hash: serverHash, timestamp: 0 }),
      push: async (_path, data) => {
        pushes++
        if (pushes === 1) {
          // Simulate a concurrent writer advancing the server between our pull and push.
          serverN = 20
          serverHash = "h20"
          throw new ConflictError()
        }
        return { hash: "ok", timestamp: 0 }
      },
    })
    const out = await mutateDoc<{ n: number }>(client, "/doc", (cur) => ({ n: (cur.data?.n ?? 0) + 1 }))
    // Second attempt re-read n=20 → wrote 21 (proves the mutator ran on fresh state).
    expect(out).toEqual({ n: 21 })
    expect(client.pullCalls).toHaveLength(2)
  })

  it("treats a 404 as an absent document the mutator can create", async () => {
    const client = createMockClient({
      pull: async () => {
        throw new StarfishHttpError(404, "not found")
      },
    })
    const out = await mutateDoc<{ created: boolean }>(client, "/doc", (cur) => {
      expect(cur.data).toBeNull()
      expect(cur.hash).toBeNull()
      return { created: true }
    })
    expect(out).toEqual({ created: true })
    expect(client.pushCalls[0]!.baseHash).toBeNull()
  })

  it("skips the write on a null (no-op) mutation", async () => {
    const client = createMockClient({
      pull: async () => ({ data: { n: 1 }, hash: "h1", timestamp: 0 }),
    })
    const out = await mutateDoc(client, "/doc", () => null)
    expect(out).toBeNull()
    expect(client.pushCalls).toHaveLength(0)
  })

  it("propagates a persistent conflict after exhausting attempts", async () => {
    const client = createMockClient({
      pull: async () => ({ data: {}, hash: "h", timestamp: 0 }),
      push: async () => {
        throw new ConflictError()
      },
    })
    await expect(
      mutateDoc(client, "/doc", () => ({ x: 1 }), { maxAttempts: 2 }),
    ).rejects.toBeInstanceOf(ConflictError)
    expect(client.pushCalls).toHaveLength(2)
  })

  it("propagates a non-conflict pull error", async () => {
    const client = createMockClient({
      pull: async () => {
        throw new StarfishHttpError(500, "boom")
      },
    })
    await expect(mutateDoc(client, "/doc", () => ({ x: 1 }))).rejects.toBeInstanceOf(StarfishHttpError)
  })
})
