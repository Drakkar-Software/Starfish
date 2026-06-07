import { describe, it, expect, vi } from "vitest"
import { createSyncRouter, type SyncRouterOptions } from "../../src/router/route-builder.js"
import type { ServerPlugin, AuthorizeContext } from "../../src/plugins.js"
import type { SyncConfig } from "../../src/config/schema.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { webcrypto } from "node:crypto"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

/** A plugin whose authorize hook rejects whenever `deny(ctx)` is true. */
function denyPlugin(deny: (ctx: AuthorizeContext) => boolean): ServerPlugin {
  return {
    name: "test-deny",
    authorize: (ctx) =>
      deny(ctx)
        ? { action: "reject", status: 403, error: "identity restricted" }
        : { action: "proceed" },
  }
}

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
    },
    {
      name: "public-data",
      storagePath: "public/data",
      readRoles: ["public"],
      writeRoles: ["self"],
      encryption: "none",
      maxBodyBytes: 1_000_000,
      allowedMimeTypes: ["application/json"],
    },
    {
      name: "docs",
      storagePath: "users/{identity}/docs/{docId}",
      readRoles: ["self"],
      writeRoles: ["self"],
      encryption: "none",
      maxBodyBytes: 1_000_000,
      allowedMimeTypes: ["application/json"],
      listable: true,
    },
    {
      name: "prefs",
      storagePath: "users/{identity}/bundle",
      bundle: "userdata",
      readRoles: ["self"],
      writeRoles: ["self"],
      encryption: "none",
      maxBodyBytes: 1_000_000,
      allowedMimeTypes: ["application/json"],
    },
    {
      name: "profile",
      storagePath: "users/{identity}/bundle",
      bundle: "userdata",
      readRoles: ["self"],
      writeRoles: ["self"],
      encryption: "none",
      maxBodyBytes: 1_000_000,
      allowedMimeTypes: ["application/json"],
    },
  ],
}

function makeRouter(plugins?: ServerPlugin[], identity = "blocked") {
  const store = new MemoryObjectStore(new Map())
  const opts: SyncRouterOptions = {
    store,
    config,
    roleResolver: async () => ({ identity, roles: ["self"] }),
    ...(plugins && { plugins }),
  }
  return { app: createSyncRouter(opts), store }
}

describe("authorize hook integration", () => {
  it("denies a pull when the hook rejects", async () => {
    const { app } = makeRouter([denyPlugin((c) => c.identity === "blocked")])
    const res = await app.request("/pull/users/blocked/settings")
    expect(res.status).toBe(403)
    expect((await res.json()).error).toBe("identity restricted")
  })

  it("allows the pull when no hook is installed", async () => {
    const { app } = makeRouter()
    const res = await app.request("/pull/users/blocked/settings")
    expect(res.status).toBe(200)
  })

  it("allows the pull when the hook proceeds", async () => {
    const { app } = makeRouter([denyPlugin(() => false)])
    const res = await app.request("/pull/users/blocked/settings")
    expect(res.status).toBe(200)
  })

  it("denies a push when the hook rejects", async () => {
    const { app } = makeRouter([denyPlugin((c) => c.action === "push")])
    const res = await app.request("/push/users/blocked/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { theme: "dark" }, baseHash: null }),
    })
    expect(res.status).toBe(403)
    expect((await res.json()).error).toBe("identity restricted")
  })

  it("denies a list when the hook rejects", async () => {
    const { app } = makeRouter([denyPlugin((c) => c.action === "list")])
    const res = await app.request("/list/users/blocked/docs")
    expect(res.status).toBe(403)
    expect((await res.json()).error).toBe("identity restricted")
  })

  it("applies to a public collection (identity is resolved despite the public fast-path)", async () => {
    const { app } = makeRouter([denyPlugin((c) => c.identity === "blocked")])
    const res = await app.request("/pull/public/data")
    expect(res.status).toBe(403)
    // sanity: without the hook the public collection is anonymously readable
    const { app: open } = makeRouter()
    expect((await open.request("/pull/public/data")).status).toBe(200)
  })

  it("returns a per-entry error for a denied batch-pull member", async () => {
    const { app } = makeRouter([denyPlugin((c) => c.collection === "settings")])
    const res = await app.request("/batch/pull?collections=settings")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.settings[0].error).toBe("identity restricted")
  })

  it("omits a restricted member from a bundle pull", async () => {
    const { app } = makeRouter([denyPlugin((c) => c.collection === "profile")])
    const res = await app.request("/pull/users/blocked/bundle")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.prefs).toBeDefined()
    expect(body.collections.profile).toBeUndefined()
  })

  it("normalizes an anonymous identity ('') to undefined in the hook context", async () => {
    // The default cap resolver represents anonymous as "" — the hook must see
    // `undefined` per the AuthorizeContext contract, on every path.
    let seen: AuthorizeContext | undefined
    const capture: ServerPlugin = {
      name: "capture",
      authorize: (ctx) => {
        seen = ctx
        return { action: "proceed" }
      },
    }
    const { app } = makeRouter([capture], "") // anonymous resolver
    const res = await app.request("/pull/public/data")
    expect(res.status).toBe(200)
    expect(seen?.identity).toBeUndefined()
  })

  it("does not deny an anonymous caller under a deny rule", async () => {
    // anonymous ("") must not match a deny list of concrete identities
    const { app } = makeRouter([denyPlugin((c) => c.identity === "someone")], "")
    const res = await app.request("/pull/public/data")
    expect(res.status).toBe(200)
  })

  it("scopes denial by action: push blocked, pull allowed", async () => {
    const { app } = makeRouter([denyPlugin((c) => c.action === "push")])
    expect((await app.request("/pull/users/blocked/settings")).status).toBe(200)
    const push = await app.request("/push/users/blocked/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })
    expect(push.status).toBe(403)
  })
})

describe("createSyncRouter restrictions footgun warning", () => {
  it("warns when config declares restrictions but no authorize hook is wired", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {})
    const store = new MemoryObjectStore(new Map())
    createSyncRouter({
      store,
      roleResolver: async () => ({ identity: "u", roles: [] }),
      config: {
        version: 1,
        collections: [
          {
            name: "c",
            storagePath: "c/{identity}",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "none",
            maxBodyBytes: 1000,
            allowedMimeTypes: ["application/json"],
            restrictions: [{ mode: "deny", identities: ["x"] }],
          },
        ],
      },
    })
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("restrictions are NOT enforced"))
    warn.mockRestore()
  })

  it("does not warn when an authorize hook is present", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {})
    makeRouter([denyPlugin(() => false)])
    const restrictionWarn = warn.mock.calls.find((c) =>
      String(c[0]).includes("restrictions are NOT enforced"),
    )
    expect(restrictionWarn).toBeUndefined()
    warn.mockRestore()
  })
})
