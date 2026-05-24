/**
 * End-to-end: the replica plugin's route hooks fire through a real
 * `createSyncRouter`, proving `beforePull` / `interceptPush` are dispatched by
 * the server's pull/push routes.
 */
import { describe, it, expect, vi } from "vitest"
import { createReplicaServerPlugin } from "../src/plugin.js"
import type { RemoteConfig } from "../src/config.js"
import { createSyncRouter, MemoryObjectStore } from "@drakkar.software/starfish-server"
import type { SyncConfig } from "@drakkar.software/starfish-server"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { webcrypto } from "node:crypto"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

function makeRouter(remote: RemoteConfig, fetchFn?: typeof fetch) {
  const store = new MemoryObjectStore()
  const config: SyncConfig = {
    version: 1,
    collections: [
      {
        name: "posts",
        storagePath: "posts/featured",
        readRoles: ["public"],
        writeRoles: ["public"],
        encryption: "none",
        maxBodyBytes: 1_000_000,
        allowedMimeTypes: ["application/json"],
      },
    ],
  }
  const replica = createReplicaServerPlugin({
    store,
    syncConfig: config,
    collections: { posts: remote },
    fetchFn,
  })
  const app = createSyncRouter({
    store,
    config,
    roleResolver: async () => ({ identity: "u", roles: ["public"] }),
    plugins: [replica],
  })
  return { app, store, replica }
}

const baseRemote = (overrides: Partial<RemoteConfig> = {}): RemoteConfig => ({
  url: "https://primary.example.com",
  pullPath: "/pull/posts/featured",
  intervalMs: 60_000,
  headers: {},
  writeMode: "pull_only",
  syncTriggers: ["scheduled"],
  ...overrides,
})

describe("replica plugin ↔ createSyncRouter", () => {
  it("rejects a pull on a push_only collection with 405", async () => {
    const { app } = makeRouter(baseRemote({ writeMode: "push_only" }))
    const res = await app.request("/pull/posts/featured")
    expect(res.status).toBe(405)
  })

  it("rejects a push on a pull_only collection with 405", async () => {
    const { app } = makeRouter(baseRemote({ writeMode: "pull_only" }))
    const res = await app.request("/push/posts/featured", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })
    expect(res.status).toBe(405)
  })

  it("syncs from primary before serving an on_pull pull", async () => {
    const fetchFn = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: { hello: "world" }, hash: "h1", timestamp: 1 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    )
    const { app } = makeRouter(baseRemote({ writeMode: "pull_only", syncTriggers: ["on_pull"] }), fetchFn)
    const res = await app.request("/pull/posts/featured")
    expect(res.status).toBe(200)
    expect(fetchFn).toHaveBeenCalledWith("https://primary.example.com/pull/posts/featured", expect.anything())
    const body = (await res.json()) as { data: Record<string, unknown> }
    expect(body.data).toEqual({ hello: "world" })
  })

  it("proxies a push_through write to the primary", async () => {
    const fetchFn = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
      const body = init?.method === "POST"
        ? { hash: "primary-hash", timestamp: 5 }
        : { data: {}, hash: "primary-hash", timestamp: 5 }
      return Promise.resolve(
        new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } }),
      )
    })
    const { app } = makeRouter(
      baseRemote({ writeMode: "push_through", pushPath: "/push/posts/featured" }),
      fetchFn,
    )
    const res = await app.request("/push/posts/featured", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    expect(body).toEqual({ hash: "primary-hash", timestamp: 5 })
    // proxied to the primary's push endpoint
    expect(fetchFn).toHaveBeenCalledWith(
      "https://primary.example.com/push/posts/featured",
      expect.objectContaining({ method: "POST" }),
    )
  })
})
