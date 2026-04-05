import { describe, it, expect } from "vitest"
import { createSyncRouter, type SyncRouterOptions, type AuthResult } from "../../src/router/route_builder.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import type { SyncConfig } from "../../src/config/schema.js"

function buildApp(
  configOverride?: Partial<SyncConfig>,
  optsOverride?: Partial<SyncRouterOptions>,
) {
  const store = new MemoryObjectStore({ data: {} })
  const config: SyncConfig = {
    version: 1,
    collections: [
      {
        name: "settings",
        storagePath: "users/{identity}/settings",
        readRoles: ["self"],
        writeRoles: ["self"],
        maxBodyBytes: 10_000,
      },
      {
        name: "public-data",
        storagePath: "public/data",
        readRoles: ["public"],
        writeRoles: ["admin"],
      },
    ],
    ...configOverride,
  }

  const roleResolver = async (request: Request): Promise<AuthResult> => {
    const auth = request.headers.get("authorization")
    if (!auth) throw new Error("No auth")
    const [identity, ...roles] = auth.split(",")
    // Filter out "self" — it's a protocol-level role added by the router, not the resolver
    return { identity, roles: roles.filter((r) => r !== "self") }
  }

  const opts: SyncRouterOptions = {
    store,
    config,
    roleResolver,
    ...optsOverride,
  }

  const app = createSyncRouter(opts)
  return { app, store }
}

async function jsonBody(resp: Response): Promise<unknown> {
  return resp.json()
}

describe("createSyncRouter", () => {
  it("GET /health returns ok", async () => {
    const { app } = buildApp()
    const resp = await app.request("/health")
    expect(resp.status).toBe(200)
    const body = (await jsonBody(resp)) as { ok: boolean; ts: number }
    expect(body.ok).toBe(true)
    expect(body.ts).toBeGreaterThan(0)
  })

  it("pull empty collection returns empty data", async () => {
    const { app } = buildApp()
    const resp = await app.request("/pull/users/alice/settings", {
      headers: { Authorization: "alice,self" },
    })
    expect(resp.status).toBe(200)
    const body = (await jsonBody(resp)) as { data: Record<string, unknown>; hash: string }
    expect(body.data).toEqual({})
    expect(body.hash).toBe("")
  })

  it("push/pull round-trip", async () => {
    const { app } = buildApp()
    const pushResp = await app.request("/push/users/alice/settings", {
      method: "POST",
      headers: {
        Authorization: "alice,self",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        data: { theme: "dark", lang: "en" },
        baseHash: null,
      }),
    })
    expect(pushResp.status).toBe(200)
    const pushBody = (await jsonBody(pushResp)) as { hash: string; timestamp: number }
    expect(pushBody.hash).toBeTruthy()

    const pullResp = await app.request("/pull/users/alice/settings", {
      headers: { Authorization: "alice,self" },
    })
    expect(pullResp.status).toBe(200)
    const pullBody = (await jsonBody(pullResp)) as { data: Record<string, unknown>; hash: string }
    expect(pullBody.data).toEqual({ theme: "dark", lang: "en" })
    expect(pullBody.hash).toBe(pushBody.hash)
  })

  it("public collection allows anonymous pull", async () => {
    const { app } = buildApp()
    const resp = await app.request("/pull/public/data")
    expect(resp.status).toBe(200)
  })

  it("non-public collection requires auth", async () => {
    const { app } = buildApp()
    const resp = await app.request("/pull/users/alice/settings")
    expect(resp.status).toBe(401)
  })

  it("wrong role gets 403", async () => {
    const { app } = buildApp()
    const resp = await app.request("/push/public/data", {
      method: "POST",
      headers: {
        Authorization: "alice,user",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ data: { key: "val" }, baseHash: null }),
    })
    expect(resp.status).toBe(403)
  })

  it("self role grants access to own path", async () => {
    const { app } = buildApp()
    const resp = await app.request("/push/users/alice/settings", {
      method: "POST",
      headers: {
        Authorization: "alice,self",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })
    expect(resp.status).toBe(200)
  })

  it("self role denies access to other's path", async () => {
    const { app } = buildApp()
    const resp = await app.request("/push/users/bob/settings", {
      method: "POST",
      headers: {
        Authorization: "alice,self",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })
    expect(resp.status).toBe(403)
  })

  it("body size limit returns 413", async () => {
    const { app } = buildApp()
    const bigData: Record<string, string> = {}
    for (let i = 0; i < 1000; i++) bigData[`key${i}`] = "x".repeat(100)
    const body = JSON.stringify({ data: bigData, baseHash: null })

    const resp = await app.request("/push/users/alice/settings", {
      method: "POST",
      headers: {
        Authorization: "alice,self",
        "Content-Type": "application/json",
        "Content-Length": String(body.length),
      },
      body,
    })
    expect(resp.status).toBe(413)
  })

  it("hash conflict returns 409", async () => {
    const { app } = buildApp()
    // First push
    await app.request("/push/users/alice/settings", {
      method: "POST",
      headers: {
        Authorization: "alice,self",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ data: { a: 1 }, baseHash: null }),
    })

    // Push with wrong hash
    const resp = await app.request("/push/users/alice/settings", {
      method: "POST",
      headers: {
        Authorization: "alice,self",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ data: { a: 2 }, baseHash: "wronghash" }),
    })
    expect(resp.status).toBe(409)
  })

  it("delegated encryption skips timestamps (skipTimestamps)", async () => {
    const { app, store } = buildApp({
      collections: [
        {
          name: "encrypted",
          storagePath: "enc/data",
          readRoles: ["public"],
          writeRoles: ["public"],
          encryption: "delegated",
        },
      ],
    })

    await app.request("/push/enc/data", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { _encrypted: "base64data" }, baseHash: null }),
    })

    const raw = await store.getString("enc/data")
    const doc = JSON.parse(raw!)
    expect(doc.timestamps).toEqual({})
  })
})
