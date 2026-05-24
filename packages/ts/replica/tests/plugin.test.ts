import { describe, it, expect, vi } from "vitest"
import { createReplicaServerPlugin } from "../src/plugin.js"
import type { RemoteConfig } from "../src/config.js"
import { MemoryObjectStore } from "@drakkar.software/starfish-server"
import type { SyncConfig, CollectionConfig } from "@drakkar.software/starfish-server"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { webcrypto } from "node:crypto"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

function col(overrides: Partial<CollectionConfig> = {}): CollectionConfig {
  return {
    name: "posts",
    storagePath: "posts/featured",
    readRoles: ["public"],
    writeRoles: ["self"],
    encryption: "none",
    maxBodyBytes: 1_000_000,
    allowedMimeTypes: ["application/json"],
    ...overrides,
  }
}

function remote(overrides: Partial<RemoteConfig> = {}): RemoteConfig {
  return {
    url: "https://primary.example.com",
    pullPath: "/pull/posts/featured",
    intervalMs: 60_000,
    headers: {},
    writeMode: "pull_only",
    syncTriggers: ["scheduled"],
    ...overrides,
  }
}

const syncConfig = (): SyncConfig => ({ version: 1, collections: [col()] })

describe("createReplicaServerPlugin", () => {
  it("throws on invalid config at construction", () => {
    expect(() =>
      createReplicaServerPlugin({
        store: new MemoryObjectStore(),
        syncConfig: syncConfig(),
        collections: { posts: remote({ writeMode: "push_through" }) }, // missing pushPath
      }),
    ).toThrow(/invalid configuration/)
  })

  it("beforePull rejects a write-only (push_only) collection with 405", async () => {
    const plugin = createReplicaServerPlugin({
      store: new MemoryObjectStore(),
      syncConfig: syncConfig(),
      collections: { posts: remote({ writeMode: "push_only" }) },
    })
    const res = await plugin.beforePull!({ collection: "posts", params: {} })
    expect(res).toEqual({ action: "reject", status: 405, error: expect.stringContaining("write-only") })
  })

  it("beforePull proceeds (and syncs) for an on_pull collection", async () => {
    const fetchFn = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: { a: 1 }, hash: "h1", timestamp: 1 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    )
    const plugin = createReplicaServerPlugin({
      store: new MemoryObjectStore(),
      syncConfig: syncConfig(),
      collections: { posts: remote({ syncTriggers: ["on_pull"] }) },
      fetchFn,
    })
    const res = await plugin.beforePull!({ collection: "posts", params: {} })
    expect(res).toEqual({ action: "proceed" })
    expect(fetchFn).toHaveBeenCalledWith("https://primary.example.com/pull/posts/featured", expect.anything())
  })

  it("beforePull proceeds for a non-remote collection", async () => {
    const plugin = createReplicaServerPlugin({
      store: new MemoryObjectStore(),
      syncConfig: syncConfig(),
      collections: { posts: remote() },
    })
    const res = await plugin.beforePull!({ collection: "something-else", params: {} })
    expect(res).toEqual({ action: "proceed" })
  })

  it("interceptPush rejects a read-only (pull_only) collection with 405", async () => {
    const plugin = createReplicaServerPlugin({
      store: new MemoryObjectStore(),
      syncConfig: syncConfig(),
      collections: { posts: remote({ writeMode: "pull_only" }) },
    })
    const res = await plugin.interceptPush!({ collection: "posts", params: {}, rawBody: "{}" })
    expect(res).toEqual({ action: "reject", status: 405, error: expect.stringContaining("read-only") })
  })

  it("interceptPush proxies a push_through write to the primary", async () => {
    const fetchFn = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
      // POST = proxied push response; GET = background sync after success
      const body = init?.method === "POST"
        ? { hash: "primary-hash", timestamp: 5 }
        : { data: {}, hash: "primary-hash", timestamp: 5 }
      return Promise.resolve(
        new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } }),
      )
    })
    const plugin = createReplicaServerPlugin({
      store: new MemoryObjectStore(),
      syncConfig: syncConfig(),
      collections: { posts: remote({ writeMode: "push_through", pushPath: "/push/posts/featured" }) },
      fetchFn,
    })
    const res = await plugin.interceptPush!({ collection: "posts", params: {}, rawBody: JSON.stringify({ data: {} }) })
    expect(res).toEqual({ action: "respond", status: 200, body: { hash: "primary-hash", timestamp: 5 } })
  })

  it("interceptPush proceeds (local write) for bidirectional and push_only", async () => {
    const plugin = createReplicaServerPlugin({
      store: new MemoryObjectStore(),
      syncConfig: syncConfig(),
      collections: {
        posts: remote({ writeMode: "bidirectional", pushPath: "/push/posts/featured" }),
      },
    })
    const res = await plugin.interceptPush!({ collection: "posts", params: {}, rawBody: "{}" })
    expect(res).toEqual({ action: "proceed" })
  })

  it("shutdown stops the manager", async () => {
    const plugin = createReplicaServerPlugin({
      store: new MemoryObjectStore(),
      syncConfig: syncConfig(),
      collections: { posts: remote() },
    })
    const stopSpy = vi.spyOn(plugin.manager, "stop")
    await plugin.shutdown!()
    expect(stopSpy).toHaveBeenCalledOnce()
  })
})
