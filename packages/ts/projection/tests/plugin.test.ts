import { describe, it, expect } from "vitest"
import { webcrypto } from "node:crypto"
import { configurePlatform, type WriteEvent } from "@drakkar.software/starfish-protocol"
import {
  createSyncRouter,
  MemoryObjectStore,
  type SyncRouterOptions,
  type AuthResult,
  type SyncConfig,
  type CollectionConfig,
} from "@drakkar.software/starfish-server"
import { createProjectionServerPlugin, type Projection } from "../src/index.js"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

const jsonCol = (overrides: Partial<CollectionConfig> = {}): CollectionConfig => ({
  name: "source",
  storagePath: "src/{id}",
  readRoles: ["self"],
  writeRoles: ["self"],
  encryption: "none",
  maxBodyBytes: 1_000_000,
  allowedMimeTypes: ["application/json"],
  ...overrides,
})

function makeRouter(args: {
  collections: CollectionConfig[]
  projections: Projection[]
}) {
  const store = new MemoryObjectStore(new Map())
  const config: SyncConfig = { version: 1, collections: args.collections }
  const opts: SyncRouterOptions = {
    store,
    config,
    roleResolver: async (): Promise<AuthResult> => ({ identity: "user-1", roles: ["self"] }),
    plugins: [createProjectionServerPlugin({ store, projections: args.projections })],
  }
  return { app: createSyncRouter(opts), store }
}

async function pushDoc(
  app: ReturnType<typeof createSyncRouter>,
  path: string,
  data: Record<string, unknown>,
) {
  // Read the current hash first so an update to an existing key passes the
  // optimistic-concurrency check (a second push with baseHash:null would 409).
  const pullPath = path.replace("/push/", "/pull/")
  const cur = await app.request(pullPath)
  const baseHash = cur.status === 200 ? ((await cur.json()).hash as string) || null : null
  return app.request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ data, baseHash }),
  })
}

describe("projection plugin — afterWrite maintains a materialized view", () => {
  it("upserts a target document derived from a source write", async () => {
    const { app } = makeRouter({
      collections: [
        jsonCol({ name: "source", storagePath: "src/{id}" }),
        jsonCol({
          name: "view",
          storagePath: "view/{id}",
          readRoles: ["self"],
          pullOnly: true,
          listable: true,
          listValues: true,
        }),
      ],
      projections: [
        {
          source: "source",
          project: (e: WriteEvent) => ({
            key: `view/${e.params.id}`,
            data: { id: e.params.id, name: (e.body?.name as string) ?? "", indexed: true },
          }),
        },
      ],
    })

    await pushDoc(app, "/push/src/a1", { name: "Alpha" })

    // The view doc is readable via a normal pull.
    const res = await app.request("/pull/view/a1")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data).toEqual({ id: "a1", name: "Alpha", indexed: true })
  })

  it("re-projects on update (last-writer-wins by key)", async () => {
    const { app } = makeRouter({
      collections: [
        jsonCol({ name: "source", storagePath: "src/{id}" }),
        jsonCol({ name: "view", storagePath: "view/{id}", pullOnly: true }),
      ],
      projections: [
        {
          source: "source",
          project: (e: WriteEvent) => ({
            key: `view/${e.params.id}`,
            data: { name: (e.body?.name as string) ?? "" },
          }),
        },
      ],
    })

    await pushDoc(app, "/push/src/a1", { name: "First" })
    await pushDoc(app, "/push/src/a1", { name: "Second" })

    const body = await (await app.request("/pull/view/a1")).json()
    expect(body.data).toEqual({ name: "Second" })
  })

  it("deletes the target document when the projection returns delete", async () => {
    const { app, store } = makeRouter({
      collections: [
        jsonCol({ name: "source", storagePath: "src/{id}" }),
        jsonCol({ name: "view", storagePath: "view/{id}", pullOnly: true }),
      ],
      projections: [
        {
          source: "source",
          project: (e: WriteEvent) =>
            e.body?.hidden === true
              ? { key: `view/${e.params.id}`, delete: true }
              : { key: `view/${e.params.id}`, data: { name: (e.body?.name as string) ?? "" } },
        },
      ],
    })

    await pushDoc(app, "/push/src/a1", { name: "Visible" })
    expect(await store.getString("view/a1")).not.toBeNull()

    await pushDoc(app, "/push/src/a1", { hidden: true })
    expect(await store.getString("view/a1")).toBeNull()
  })

  it("ignores the event when the projection returns null", async () => {
    const { store } = makeRouter({ collections: [], projections: [] })
    void store
    const { app, store: s2 } = makeRouter({
      collections: [
        jsonCol({ name: "source", storagePath: "src/{id}" }),
        jsonCol({ name: "view", storagePath: "view/{id}", pullOnly: true }),
      ],
      projections: [{ source: "source", project: () => null }],
    })

    await pushDoc(app, "/push/src/a1", { name: "Alpha" })
    expect(await s2.getString("view/a1")).toBeNull()
  })

  it("only fires for collections named in the projection's source", async () => {
    const { app, store } = makeRouter({
      collections: [
        jsonCol({ name: "watched", storagePath: "watched/{id}" }),
        jsonCol({ name: "other", storagePath: "other/{id}" }),
        jsonCol({ name: "view", storagePath: "view/{id}", pullOnly: true }),
      ],
      projections: [
        {
          source: "watched",
          project: (e: WriteEvent) => ({ key: `view/${e.params.id}`, data: { ok: true } }),
        },
      ],
    })

    await pushDoc(app, "/push/other/a1", { name: "x" })
    expect(await store.getString("view/a1")).toBeNull()

    await pushDoc(app, "/push/watched/a1", { name: "x" })
    expect(await store.getString("view/a1")).not.toBeNull()
  })

  it("supports multiple source collections in one projection", async () => {
    const { app, store } = makeRouter({
      collections: [
        jsonCol({ name: "a", storagePath: "a/{id}" }),
        jsonCol({ name: "b", storagePath: "b/{id}" }),
        jsonCol({ name: "view", storagePath: "view/{id}", pullOnly: true }),
      ],
      projections: [
        {
          source: ["a", "b"],
          project: (e: WriteEvent) => ({
            key: `view/${e.params.id}`,
            data: { from: e.collection },
          }),
        },
      ],
    })

    await pushDoc(app, "/push/a/k", { v: 1 })
    expect((await (await app.request("/pull/view/k")).json()).data).toEqual({ from: "a" })

    await pushDoc(app, "/push/b/k", { v: 2 })
    expect((await (await app.request("/pull/view/k")).json()).data).toEqual({ from: "b" })
    void store
  })

  it("the materialized view is enumerable via list?include=values", async () => {
    const { app } = makeRouter({
      collections: [
        jsonCol({ name: "source", storagePath: "src/{id}" }),
        jsonCol({
          name: "view",
          storagePath: "view/{id}",
          readRoles: ["self"],
          pullOnly: true,
          listable: true,
          listValues: true,
        }),
      ],
      projections: [
        {
          source: "source",
          project: (e: WriteEvent) => ({
            key: `view/${e.params.id}`,
            data: { id: e.params.id, name: (e.body?.name as string) ?? "" },
          }),
        },
      ],
    })

    await pushDoc(app, "/push/src/a1", { name: "Alpha" })
    await pushDoc(app, "/push/src/a2", { name: "Beta" })

    const body = await (await app.request("/list/view?include=values")).json()
    expect(body.items.map((i: { key: string }) => i.key)).toEqual(["a1", "a2"])
    expect(body.items.map((i: { data: { name: string } }) => i.data.name)).toEqual(["Alpha", "Beta"])
  })

  it("a pullOnly target view rejects direct client writes", async () => {
    const { app } = makeRouter({
      collections: [
        jsonCol({ name: "source", storagePath: "src/{id}" }),
        jsonCol({ name: "view", storagePath: "view/{id}", pullOnly: true }),
      ],
      projections: [
        { source: "source", project: (e) => ({ key: `view/${e.params.id}`, data: { ok: true } }) },
      ],
    })

    // The projection populates it…
    await pushDoc(app, "/push/src/a1", { name: "x" })
    expect((await app.request("/pull/view/a1")).status).toBe(200)

    // …but a client cannot push to it directly (pullOnly → no push route).
    const res = await pushDoc(app, "/push/view/a1", { tampered: true })
    expect(res.status).toBeGreaterThanOrEqual(400)
  })

  it("a projection failure does not break the originating client write", async () => {
    const { app } = makeRouter({
      collections: [jsonCol({ name: "source", storagePath: "src/{id}" })],
      projections: [
        {
          source: "source",
          project: () => {
            throw new Error("boom")
          },
        },
      ],
    })

    const res = await pushDoc(app, "/push/src/a1", { name: "x" })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.hash).toHaveLength(64)
  })
})
