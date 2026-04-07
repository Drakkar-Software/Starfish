import { describe, it, expect } from "vitest"
import { SyncManager } from "../src/sync.js"
import { StarfishClient } from "../src/client.js"
import {
  createMockClient,
  createMockFetch,
  createConflictFetch,
} from "../src/testing.js"

describe("createMockClient", () => {
  it("creates a client with default pull/push", async () => {
    const client = createMockClient()
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })

    const pullResult = await sync.pull()
    expect(pullResult.data).toEqual({})
    expect(pullResult.hash).toBe("mock-hash")

    const pushResult = await sync.push({ key: "value" })
    expect(pushResult.hash).toBe("mock-push-hash")
  })

  it("tracks pull and push calls", async () => {
    const client = createMockClient()
    const sync = new SyncManager({
      client,
      pullPath: "/pull/settings",
      pushPath: "/push/settings",
    })

    await sync.pull()
    await sync.push({ x: 1 })

    expect(client.pullCalls).toHaveLength(1)
    expect(client.pullCalls[0].path).toBe("/pull/settings")

    expect(client.pushCalls).toHaveLength(1)
    expect(client.pushCalls[0].data).toEqual({ x: 1 })
  })

  it("supports custom pull/push overrides", async () => {
    const client = createMockClient({
      pull: async () => ({
        data: { custom: true },
        hash: "custom-hash",
        timestamp: 42,
      }),
    })

    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })

    const result = await sync.pull()
    expect(result.data).toEqual({ custom: true })
  })
})

describe("createMockFetch", () => {
  it("returns pull response for /pull/ URLs", async () => {
    const fetch = createMockFetch(
      { data: { key: "val" }, hash: "h1", timestamp: 100 },
    )

    const client = new StarfishClient({
      baseUrl: "https://example.com",
      fetch,
    })

    const result = await client.pull("/pull/test")
    expect(result.data).toEqual({ key: "val" })
    expect(result.hash).toBe("h1")
  })

  it("returns push response for non-pull URLs", async () => {
    const fetch = createMockFetch(
      undefined,
      { hash: "pushed", timestamp: 200 },
    )

    const client = new StarfishClient({
      baseUrl: "https://example.com",
      fetch,
    })

    const result = await client.push("/push/test", { data: "x" }, null)
    expect(result.hash).toBe("pushed")
  })
})

describe("createConflictFetch", () => {
  it("returns 409 on first push then succeeds", async () => {
    const fetch = createConflictFetch(
      { data: { remote: true }, hash: "remote-hash", timestamp: 100 },
      { hash: "resolved", timestamp: 200 },
    )

    const client = new StarfishClient({
      baseUrl: "https://example.com",
      fetch,
    })

    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      maxRetries: 3,
    })

    // First pull to seed state
    await sync.pull()

    // Push should hit conflict, retry, and succeed
    const result = await sync.push({ local: true })
    expect(result.hash).toBe("resolved")
  })
})
