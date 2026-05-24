import { describe, it, expect } from "vitest"
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

function makeConfig(): SyncConfig {
  return {
    version: 1,
    collections: [
      {
        // Delegated collection. The keyring sibling lives at
        // `users/{identity}/notes/_keyring` — same prefix tree.
        name: "notes",
        storagePath: "users/{identity}/notes",
        readRoles: ["self"],
        writeRoles: ["self"],
        encryption: "delegated",
        maxBodyBytes: 1_000_000,
        allowedMimeTypes: ["application/json"],
      },
      // Sibling collection that owns the keyring document. The router
      // doesn't need to know about it for the ?withKeyring=1 shortcut —
      // the server reads directly from the store — but defining it here
      // mirrors a realistic delegated setup.
      {
        name: "notes_keyring",
        storagePath: "users/{identity}/notes/_keyring",
        readRoles: ["self"],
        writeRoles: ["self"],
        encryption: "none",
        maxBodyBytes: 1_000_000,
        allowedMimeTypes: ["application/json"],
      },
    ],
  }
}

function makeRouter() {
  const store = new MemoryObjectStore(new Map())
  const opts: SyncRouterOptions = {
    store,
    config: makeConfig(),
    roleResolver: async () => ({ identity: "user-1", roles: ["self"] }),
  }
  return { app: createSyncRouter(opts), store, opts }
}

async function pushData(app: any, path: string, data: Record<string, unknown>): Promise<string> {
  const res = await app.request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ data, baseHash: null }),
  })
  expect(res.status).toBe(200)
  const body = await res.json() as { hash: string }
  return body.hash
}

describe("withKeyring pull optimization", () => {
  it("default response has no keyring field", async () => {
    const { app } = makeRouter()
    await pushData(app, "/push/users/user-1/notes", { _encrypted: "ct", _epoch: 1 })
    await pushData(app, "/push/users/user-1/notes/_keyring", { v: 1, currentEpoch: 1 })

    const res = await app.request("/pull/users/user-1/notes")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data).toEqual({ _encrypted: "ct", _epoch: 1 })
    expect("keyring" in body).toBe(false)
  })

  it("withKeyring=1 returns data and keyring", async () => {
    const { app } = makeRouter()
    await pushData(app, "/push/users/user-1/notes", { _encrypted: "ct", _epoch: 3 })
    await pushData(app, "/push/users/user-1/notes/_keyring", {
      v: 1,
      currentEpoch: 3,
      epochs: { "3": { wraps: {} } },
    })

    const res = await app.request("/pull/users/user-1/notes?withKeyring=1")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data).toEqual({ _encrypted: "ct", _epoch: 3 })
    expect(body.keyring).not.toBeNull()
    expect(body.keyring.data).toEqual({ v: 1, currentEpoch: 3, epochs: { "3": { wraps: {} } } })
    expect(typeof body.keyring.hash).toBe("string")
    expect(body.keyring.hash.length).toBeGreaterThan(0)
    expect(typeof body.keyring.timestamp).toBe("number")
    // Server keyring projection drops author fields.
    expect("authorPubkey" in body.keyring).toBe(false)
    expect("authorSignature" in body.keyring).toBe(false)
  })

  it("withKeyring=1 returns keyring:null when keyring doc missing", async () => {
    const { app } = makeRouter()
    await pushData(app, "/push/users/user-1/notes", { _encrypted: "ct", _epoch: 1 })

    const res = await app.request("/pull/users/user-1/notes?withKeyring=1")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data).toEqual({ _encrypted: "ct", _epoch: 1 })
    expect(body.keyring).toBeNull()
  })

  it("withKeyring=true is treated as on", async () => {
    const { app } = makeRouter()
    await pushData(app, "/push/users/user-1/notes", { _encrypted: "ct", _epoch: 1 })
    await pushData(app, "/push/users/user-1/notes/_keyring", { v: 1, currentEpoch: 1 })

    const res = await app.request("/pull/users/user-1/notes?withKeyring=true")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.keyring).not.toBeNull()
    expect(body.keyring.data).toMatchObject({ v: 1 })
  })

  it("withKeyring=0 is treated as off (no keyring in response)", async () => {
    const { app } = makeRouter()
    await pushData(app, "/push/users/user-1/notes", { _encrypted: "ct", _epoch: 1 })
    await pushData(app, "/push/users/user-1/notes/_keyring", { v: 1, currentEpoch: 1 })

    const res = await app.request("/pull/users/user-1/notes?withKeyring=0")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect("keyring" in body).toBe(false)
  })

  it("degrades gracefully (keyring:null) when the store throws reading the keyring", async () => {
    // Store that throws on any `/_keyring` read — models e.g. a filesystem store
    // hitting a leaf-file data path. The pull must not 500.
    class RaisingKeyringStore extends MemoryObjectStore {
      async getString(key: string, context?: any): Promise<string | null> {
        if (key.endsWith("/_keyring")) throw new Error(`ENOTDIR ${key}`)
        return super.getString(key, context)
      }
    }
    const store = new RaisingKeyringStore(new Map())
    const opts: SyncRouterOptions = {
      store,
      config: makeConfig(),
      roleResolver: async () => ({ identity: "user-1", roles: ["self"] }),
    }
    const app = createSyncRouter(opts)
    await pushData(app, "/push/users/user-1/notes", { _encrypted: "ct", _epoch: 1 })

    const res = await app.request("/pull/users/user-1/notes?withKeyring=1")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.keyring).toBeNull()
  })
})

// ?withKeyring=1 must honour the caller's cap-cert scope. The keyring document
// is owner-only; a cap that denies `<col>/_keyring` must not read it via the
// withKeyring sibling shortcut.
describe("withKeyring honours cap-cert scope", () => {
  function makeScopedApp(scopePaths: string[] | undefined, dataPath = "users/{identity}/notes") {
    const store = new MemoryObjectStore(new Map())
    const config: SyncConfig = {
      version: 1,
      collections: [
        {
          name: "notes",
          storagePath: dataPath,
          readRoles: ["self"],
          writeRoles: ["self"],
          encryption: "delegated",
          maxBodyBytes: 1_000_000,
          allowedMimeTypes: ["application/json"],
        },
        {
          name: "notes_keyring",
          storagePath: `${dataPath}/_keyring`,
          readRoles: ["self"],
          writeRoles: ["self"],
          encryption: "none",
          maxBodyBytes: 1_000_000,
          allowedMimeTypes: ["application/json"],
        },
      ],
    }
    const opts: SyncRouterOptions = {
      store,
      config,
      roleResolver: async () => ({ identity: "user-1", roles: ["self"], scopePaths }),
    }
    return createSyncRouter(opts)
  }

  it("omits the keyring when the cap scope denies it", async () => {
    const app = makeScopedApp(["users/user-1/notes/**", "!users/user-1/notes/_keyring"])
    await pushData(app, "/push/users/user-1/notes", { _encrypted: "ct" })
    await pushData(app, "/push/users/user-1/notes/_keyring", { v: 1, currentEpoch: 1 })

    const res = await app.request("/pull/users/user-1/notes?withKeyring=1")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data).toEqual({ _encrypted: "ct" })
    // Owner-only keyring is NOT leaked despite the document existing.
    expect(body.keyring ?? null).toBeNull()
  })

  it("includes the keyring when the cap scope allows it", async () => {
    const app = makeScopedApp(["users/user-1/notes/**"])
    await pushData(app, "/push/users/user-1/notes", { _encrypted: "ct" })
    await pushData(app, "/push/users/user-1/notes/_keyring", { v: 1, currentEpoch: 1 })

    const res = await app.request("/pull/users/user-1/notes?withKeyring=1")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.keyring).not.toBeNull()
    expect(body.keyring.data).toMatchObject({ v: 1 })
  })

  it("omits the keyring for a root-allow + keyring-deny custom scope (exploit shape)", async () => {
    const app = makeScopedApp(["notes", "notes/**", "!notes/_keyring"], "notes")
    await pushData(app, "/push/notes", { _encrypted: "ct" })
    await pushData(app, "/push/notes/_keyring", { v: 9 })

    const res = await app.request("/pull/notes?withKeyring=1")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data).toEqual({ _encrypted: "ct" })
    expect(body.keyring ?? null).toBeNull()
  })

  it("includes the keyring when the resolver carries no scope (role-based auth)", async () => {
    const app = makeScopedApp(undefined)
    await pushData(app, "/push/users/user-1/notes", { _encrypted: "ct" })
    await pushData(app, "/push/users/user-1/notes/_keyring", { v: 7, currentEpoch: 1 })

    const res = await app.request("/pull/users/user-1/notes?withKeyring=1")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.keyring).not.toBeNull()
    expect(body.keyring.data).toMatchObject({ v: 7 })
  })
})
