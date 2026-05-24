import { describe, it, expect, vi } from "vitest"
import { ReplicaManager } from "../src/manager.js"
import type { RemoteCollection } from "../src/config.js"
import { MemoryObjectStore } from "@drakkar.software/starfish-server"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { webcrypto } from "node:crypto"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

function makeRemoteCol(overrides: Partial<RemoteCollection> = {}): RemoteCollection {
  return {
    name: "remote-data",
    storagePath: "data",
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
    const store = new MemoryObjectStore()
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
    const store = new MemoryObjectStore()
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
    const store = new MemoryObjectStore()
    const col = makeRemoteCol({
      remote: {
        ...makeRemoteCol().remote,
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
    const store = new MemoryObjectStore()
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
    const store = new MemoryObjectStore()
    const manager = new ReplicaManager(store, [])
    await expect(manager.syncNow("nonexistent")).rejects.toThrow("Unknown remote collection")
  })

  it("bidirectional mode merges local and remote", async () => {
    const store = new MemoryObjectStore()
    const col = makeRemoteCol({
      remote: {
        ...makeRemoteCol().remote,
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

  it("strips prototype-pollution keys from primary data before storing (pull_only)", async () => {
    const store = new MemoryObjectStore()
    const col = makeRemoteCol() // pull_only → writes primary data verbatim path
    // Build the body by hand so `__proto__` is an OWN key after JSON.parse.
    const malicious =
      '{"data":{"safe":1,"__proto__":{"polluted":true}},"hash":"h1","timestamp":1}'
    const mockFetch = vi.fn().mockResolvedValue(
      new Response(malicious, { status: 200, headers: { "Content-Type": "application/json" } }),
    )
    const manager = new ReplicaManager(store, [col], { fetchFn: mockFetch })
    await manager.syncNow("remote-data")

    const raw = await store.getString("data")
    expect(raw).not.toBeNull()
    const doc = JSON.parse(raw!)
    expect(doc.data.safe).toBe(1)
    expect(Object.prototype.hasOwnProperty.call(doc.data, "__proto__")).toBe(false)
    expect((Object.prototype as Record<string, unknown>).polluted).toBeUndefined()
  })

  // Regression: a corrupt local replica document is recovered by overwriting it on
  // sync. `_doSync` passes `baseHash = currentLocalHash` ("" for a corrupt/empty
  // read); push() treats baseHash="" the same as no hash when currentHash is also
  // "". Before the fix the manager coerced `currentLocalHash || null` → null, and
  // push() rejects baseHash=null when a (corrupt) doc is present, so sync threw
  // "Concurrent write" every cycle and the replica was permanently stuck.
  it("recovers from a corrupt local document by overwriting it on sync", async () => {
    const store = new MemoryObjectStore()
    const col = makeRemoteCol() // pull_only → writes primary data verbatim path
    await store.put("data", "{ this is not valid json") // a previous crash left this
    const mockFetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({ data: { x: 1 }, hash: "h1", timestamp: 1000 }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    )
    const manager = new ReplicaManager(store, [col], { fetchFn: mockFetch })
    await manager.syncNow("remote-data") // must not throw — the corrupt doc is recoverable
    const doc = JSON.parse((await store.getString("data"))!)
    expect(doc.data).toEqual({ x: 1 })
  })

  it("converges on repeated bidirectional sync (the re-merge is idempotent and lossless)", async () => {
    // local and remote diverge; the merged doc's hash differs from the primary's,
    // so each sync re-pulls and re-merges. Pin that this loop is stable: the
    // second cycle produces byte-identical data (no drift, no key loss/growth).
    const store = new MemoryObjectStore()
    const col = makeRemoteCol({
      remote: { ...makeRemoteCol().remote, writeMode: "bidirectional", pushPath: "/push/data" },
    })
    await store.put("data", JSON.stringify({
      v: 1, data: { local: "value", shared: "old" }, timestamps: {}, hash: "local-hash",
    }))
    // Fresh Response per call — a Response body can only be read once.
    const mockFetch = vi.fn().mockImplementation(() =>
      Promise.resolve(
        new Response(
          JSON.stringify({ data: { remote: "value", shared: "new" }, hash: "remote-hash", timestamp: 1000 }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    )
    const manager = new ReplicaManager(store, [col], { fetchFn: mockFetch })
    await manager.syncNow("remote-data")
    const after1 = JSON.parse((await store.getString("data"))!).data
    await manager.syncNow("remote-data")
    const after2 = JSON.parse((await store.getString("data"))!).data
    expect(after2).toEqual(after1) // idempotent: no drift across cycles
    expect(after1).toEqual({ local: "value", remote: "value", shared: "new" }) // remote wins `shared`, local-only key kept
  })

  it("rejects a primary push response with an unexpected shape", async () => {
    const store = new MemoryObjectStore()
    const col = makeRemoteCol({
      remote: {
        url: "https://primary.example.com",
        pullPath: "/pull/data",
        pushPath: "/push/data",
        intervalMs: 60_000,
        headers: {},
        writeMode: "push_through",
        syncTriggers: [],
      },
    })
    // Primary replies 200 but with a body that is not a valid push result.
    const mockFetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ unexpected: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    )
    const manager = new ReplicaManager(store, [col], { fetchFn: mockFetch })
    const result = await manager.proxyPush(
      "remote-data",
      JSON.stringify({ data: { x: 1 }, baseHash: null }),
    )
    expect(result.status).toBe(502)
  })
})
