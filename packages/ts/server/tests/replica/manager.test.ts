import { describe, it, expect, vi } from "vitest"
import { ReplicaManager } from "../../src/replica/manager.js"
import { createIsolatedStore } from "../helpers.js"
import type { CollectionConfig } from "../../src/config/schema.js"
import { configurePlatform } from "@drakkarsoftware/starfish-protocol"
import { webcrypto } from "node:crypto"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

function makeRemoteCol(overrides: Partial<CollectionConfig> = {}): CollectionConfig {
  return {
    name: "remote-data",
    storagePath: "data",
    readRoles: ["self"],
    writeRoles: ["self"],
    encryption: "none",
    maxBodyBytes: 1_000_000,
    allowedMimeTypes: ["application/json"],
    remote: {
      url: "https://primary.example.com",
      pullPath: "/pull/data",
      intervalMs: 60_000,
      headers: { Authorization: "Bearer token" },
      writeMode: "pull_only",
      syncTriggers: ["on_pull"],
    },
    ...overrides,
  }
}

describe("ReplicaManager", () => {
  it("syncs data from primary on syncNow", async () => {
    const store = createIsolatedStore()
    const col = makeRemoteCol()

    const mockFetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({ data: { hello: "world" }, hash: "abc123", timestamp: 1000 }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    )

    const manager = new ReplicaManager(store, [col], { fetchFn: mockFetch })
    await manager.syncNow("remote-data")

    expect(mockFetch).toHaveBeenCalledOnce()
    expect(mockFetch.mock.calls[0]![0]).toBe("https://primary.example.com/pull/data")

    // Data should be stored locally
    const raw = await store.getString("data")
    expect(raw).not.toBeNull()
    const doc = JSON.parse(raw!)
    expect(doc.data).toEqual({ hello: "world" })
  })

  it("skips sync when primary hash unchanged", async () => {
    const store = createIsolatedStore()
    const col = makeRemoteCol()

    const primaryData = { data: { x: 1 }, hash: "fixed-hash", timestamp: 1000 }
    const mockFetch = vi.fn().mockImplementation(() =>
      Promise.resolve(
        new Response(JSON.stringify(primaryData), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    )

    const manager = new ReplicaManager(store, [col], { fetchFn: mockFetch })
    await manager.syncNow("remote-data")
    await manager.syncNow("remote-data")

    // Second sync should detect hash hasn't changed and skip
    expect(mockFetch).toHaveBeenCalledTimes(2)
  })

  it("onPull respects cooldown", async () => {
    const store = createIsolatedStore()
    const col = makeRemoteCol({
      remote: {
        ...makeRemoteCol().remote!,
        onPullMinIntervalMs: 60_000,
      },
    })

    const mockFetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({ data: { x: 1 }, hash: "h1", timestamp: 1000 }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    )

    const manager = new ReplicaManager(store, [col], { fetchFn: mockFetch })
    await manager.onPull("remote-data")
    await manager.onPull("remote-data")

    // Second onPull should be skipped due to cooldown
    expect(mockFetch).toHaveBeenCalledTimes(1)
  })

  it("syncAll syncs all remote collections", async () => {
    const store = createIsolatedStore()
    const col1 = makeRemoteCol({ name: "col-1", storagePath: "col1" })
    const col2 = makeRemoteCol({ name: "col-2", storagePath: "col2" })

    let callCount = 0
    const mockFetch = vi.fn().mockImplementation(() => {
      callCount++
      return Promise.resolve(
        new Response(
          JSON.stringify({ data: { n: callCount }, hash: `h${callCount}`, timestamp: 1000 }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      )
    })

    const manager = new ReplicaManager(store, [col1, col2], { fetchFn: mockFetch })
    await manager.syncAll()

    expect(mockFetch).toHaveBeenCalledTimes(2)
  })

  it("throws for unknown collection", async () => {
    const store = createIsolatedStore()
    const manager = new ReplicaManager(store, [])
    await expect(manager.syncNow("nonexistent")).rejects.toThrow("Unknown remote collection")
  })

  it("bidirectional mode merges local and remote", async () => {
    const store = createIsolatedStore()
    const col = makeRemoteCol({
      remote: {
        ...makeRemoteCol().remote!,
        writeMode: "bidirectional",
        pushPath: "/push/data",
      },
    })

    // Pre-populate local data
    await store.put("data", JSON.stringify({
      v: 1,
      data: { local: "value", shared: "old" },
      timestamps: {},
      hash: "local-hash",
    }))

    const mockFetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({ data: { remote: "value", shared: "new" }, hash: "remote-hash", timestamp: 1000 }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    )

    const manager = new ReplicaManager(store, [col], { fetchFn: mockFetch })
    await manager.syncNow("remote-data")

    const raw = await store.getString("data")
    const doc = JSON.parse(raw!)
    // deepMerge: remote wins, but local-only keys preserved
    expect(doc.data.remote).toBe("value")
    expect(doc.data.local).toBe("value")
    expect(doc.data.shared).toBe("new")
  })
})
