/**
 * Tests for TTL enforcement in the pull route.
 *
 * The TTL check must compare the *stored* document timestamp against
 * the current time — not the current time against itself (which would
 * always be ~0 and never trigger expiry).
 */
import { describe, it, expect, vi, afterEach } from "vitest"
import { createSyncRouter, type SyncRouterOptions } from "../../src/router/route-builder.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import type { SyncConfig } from "../../src/config/schema.js"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { webcrypto } from "node:crypto"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

function makeRouter(ttlMs: number | undefined) {
  const store = new MemoryObjectStore(new Map())
  const config: SyncConfig = {
    version: 1,
    collections: [
      {
        name: "settings",
        storagePath: "users/{identity}/settings",
        readRoles: ["self"],
        writeRoles: ["self"],
        encryption: "none",
        maxBodyBytes: 1_000_000,
        allowedMimeTypes: ["application/json"],
        ttlMs,
      },
    ],
  }
  const opts: SyncRouterOptions = {
    store,
    config,
    roleResolver: async () => ({ identity: "user-1", roles: ["self"] }),
  }
  return { app: createSyncRouter(opts), store }
}

describe("TTL router enforcement", () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it("returns full data for a non-expired document", async () => {
    const { app } = makeRouter(60_000)
    await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { theme: "dark" }, baseHash: null }),
    })
    const res = await app.request("/pull/users/user-1/settings")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data).toEqual({ theme: "dark" })
  })

  it("returns empty data for an expired document", async () => {
    vi.useFakeTimers()

    // Push at t=1000 — stored timestamps will be 1000 (non-zero, not the
    // "never written" sentinel that isExpired() guards against)
    vi.setSystemTime(1_000)
    const { app } = makeRouter(1_000) // 1 s TTL
    await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { secret: "value" }, baseHash: null }),
    })

    // Pull at t=3000 — 2 s after push, well past the 1 s TTL
    vi.setSystemTime(3_000)
    const res = await app.request("/pull/users/user-1/settings")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data).toEqual({})
    expect(body.hash).toBe("")
  })

  it("returns data normally for a collection without TTL", async () => {
    const { app } = makeRouter(undefined)
    await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })
    const res = await app.request("/pull/users/user-1/settings")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data).toEqual({ x: 1 })
  })
})
