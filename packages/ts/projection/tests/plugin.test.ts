import { describe, it, expect } from "vitest"
import { webcrypto } from "node:crypto"
import { configurePlatform, type WriteEvent } from "@drakkar.software/starfish-protocol"
import {
  createSyncRouter,
  MemoryObjectStore,
  type ObjectStore,
  type StoreContext,
  type SyncRouterOptions,
  type AuthResult,
  type SyncConfig,
  type CollectionConfig,
} from "@drakkar.software/starfish-server"
import {
  createProjectionServerPlugin,
  type Projection,
  type ProjectionItem,
  type ProjectionPluginOptions,
} from "../src/index.js"

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

/** A source collection and a single-document list target. The target has a
 *  fixed (param-less) storagePath, so the client pulls the whole list in one GET. */
const sourceAndList = (): CollectionConfig[] => [
  jsonCol({ name: "products", storagePath: "products/{id}" }),
  jsonCol({ name: "catalog", storagePath: "catalog", pullOnly: true }),
]

function makeRouter(args: {
  collections: CollectionConfig[]
  projections: Projection[]
  store?: ObjectStore
  pluginOpts?: Partial<Omit<ProjectionPluginOptions, "store" | "projections">>
}) {
  const store = args.store ?? new MemoryObjectStore(new Map())
  const config: SyncConfig = { version: 1, collections: args.collections }
  const opts: SyncRouterOptions = {
    store,
    config,
    roleResolver: async (): Promise<AuthResult> => ({ identity: "user-1", roles: ["self"] }),
    plugins: [
      createProjectionServerPlugin({ store, projections: args.projections, ...args.pluginOpts }),
    ],
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

/** Read a target list document straight from the store. */
async function readList(store: ObjectStore, key: string): Promise<ProjectionItem[]> {
  const raw = await store.getString(key)
  if (!raw) return []
  return (JSON.parse(raw).data as { items: ProjectionItem[] }).items
}

const ids = (items: ProjectionItem[]) => items.map((i) => i.id)

// A projection that mirrors each product as a `{ id, value:{ name } }` entry in
// the `catalog` list, treating `{ deleted: true }` as a removal.
const catalogProjection: Projection = {
  source: "products",
  target: "catalog",
  project: (e: WriteEvent) =>
    e.body?.deleted === true
      ? { id: e.params.id, remove: true }
      : { id: e.params.id, value: { name: (e.body?.name as string) ?? "" } },
}

describe("projection plugin — afterWrite maintains an incremental list", () => {
  it("appends entries to the list and serves the whole list from one pull", async () => {
    const { app, store } = makeRouter({
      collections: sourceAndList(),
      projections: [catalogProjection],
    })

    await pushDoc(app, "/push/products/a", { name: "Alpha" })
    await pushDoc(app, "/push/products/b", { name: "Beta" })

    // Insertion-ordered, nested { id, value }.
    expect(await readList(store, "catalog")).toEqual([
      { id: "a", value: { name: "Alpha" } },
      { id: "b", value: { name: "Beta" } },
    ])

    // The client reads the whole list in a single GET of the one list document.
    const body = await (await app.request("/pull/catalog")).json()
    expect(body.data.items).toEqual([
      { id: "a", value: { name: "Alpha" } },
      { id: "b", value: { name: "Beta" } },
    ])
  })

  it("updates an entry in place on re-projection, keeping its position", async () => {
    const { app, store } = makeRouter({
      collections: sourceAndList(),
      projections: [catalogProjection],
    })

    await pushDoc(app, "/push/products/a", { name: "Alpha" })
    await pushDoc(app, "/push/products/b", { name: "Beta" })
    await pushDoc(app, "/push/products/a", { name: "Alpha v2" })

    const items = await readList(store, "catalog")
    expect(ids(items)).toEqual(["a", "b"]) // position preserved, not moved to end
    expect(items[0].value).toEqual({ name: "Alpha v2" }) // value fully replaced
  })

  it("removes an entry on a tombstone op; the list doc survives when emptied", async () => {
    const { app, store } = makeRouter({
      collections: sourceAndList(),
      projections: [catalogProjection],
    })

    await pushDoc(app, "/push/products/a", { name: "Alpha" })
    await pushDoc(app, "/push/products/b", { name: "Beta" })
    await pushDoc(app, "/push/products/a", { deleted: true })
    expect(ids(await readList(store, "catalog"))).toEqual(["b"])

    // Removing an id that isn't present is a no-op (no spurious write/error).
    await pushDoc(app, "/push/products/zzz", { deleted: true })
    expect(ids(await readList(store, "catalog"))).toEqual(["b"])

    // Emptying the list leaves an empty list document, not a 404.
    await pushDoc(app, "/push/products/b", { deleted: true })
    expect(await readList(store, "catalog")).toEqual([])
    expect((await app.request("/pull/catalog")).status).toBe(200)
  })

  it("ignores the event when the projection returns null", async () => {
    const { app, store } = makeRouter({
      collections: sourceAndList(),
      projections: [{ source: "products", target: "catalog", project: () => null }],
    })

    await pushDoc(app, "/push/products/a", { name: "Alpha" })
    expect(await store.getString("catalog")).toBeNull()
  })

  it("a target function shards entries into per-key lists across multiple sources", async () => {
    const { app, store } = makeRouter({
      collections: [
        jsonCol({ name: "products", storagePath: "products/{tenant}/{id}" }),
        jsonCol({ name: "services", storagePath: "services/{tenant}/{id}" }),
      ],
      projections: [
        {
          source: ["products", "services"],
          // Shard one list per tenant; ignore writes with no tenant.
          target: (e: WriteEvent) => (e.params.tenant ? `catalog/${e.params.tenant}` : null),
          project: (e: WriteEvent) => ({
            id: e.params.id,
            value: { kind: e.collection, name: (e.body?.name as string) ?? "" },
          }),
        },
      ],
    })

    await pushDoc(app, "/push/products/t1/p1", { name: "P1" })
    await pushDoc(app, "/push/services/t1/s1", { name: "S1" })
    await pushDoc(app, "/push/products/t2/p2", { name: "P2" })

    // t1's list holds both a product and a service; t2 is a separate list.
    const t1 = await readList(store, "catalog/t1")
    expect(t1).toEqual([
      { id: "p1", value: { kind: "products", name: "P1" } },
      { id: "s1", value: { kind: "services", name: "S1" } },
    ])
    expect(ids(await readList(store, "catalog/t2"))).toEqual(["p2"])
  })

  it("client enumerates and fetches all shards via the list endpoint", async () => {
    // Shard a product catalog by category (the documented manual-sharding pattern).
    const { app } = makeRouter({
      collections: [
        jsonCol({ name: "products", storagePath: "products/{id}" }),
        jsonCol({ name: "catalog", storagePath: "catalog/{category}", pullOnly: true, listable: true }),
      ],
      projections: [
        {
          source: "products",
          target: (e: WriteEvent) => (e.body?.category ? `catalog/${e.body.category}` : null),
          project: (e: WriteEvent) => ({ id: e.params.id, value: { name: e.body?.name } }),
        },
      ],
    })

    await pushDoc(app, "/push/products/p1", { name: "Novel", category: "books" })
    await pushDoc(app, "/push/products/p2", { name: "Phone", category: "electronics" })
    await pushDoc(app, "/push/products/p3", { name: "Comic", category: "books" })

    // Discover shards via the list endpoint.
    const shards: string[] = (await (await app.request("/list/catalog")).json()).items
    expect([...shards].sort()).toEqual(["books", "electronics"])

    // Pull each shard and concatenate to reconstruct the whole list.
    const all: ProjectionItem[] = []
    for (const cat of shards) {
      const body = await (await app.request(`/pull/catalog/${cat}`)).json()
      all.push(...(body.data.items as ProjectionItem[]))
    }
    expect(all.map((i) => i.id).sort()).toEqual(["p1", "p2", "p3"])
  })

  it("concurrent writes to one list do not lose updates (CAS retry)", async () => {
    // Injects a competing write to the list between the plugin's pull and its
    // push, exactly once, forcing one hash-mismatch retry.
    class OneShotConflictStore extends MemoryObjectStore {
      private armedKey: string | null = null
      private competing: string | null = null
      private calls = 0
      arm(key: string, competing: string) {
        this.armedKey = key
        this.competing = competing
        this.calls = 0
      }
      override async getString(key: string, ctx?: StoreContext): Promise<string | null> {
        if (key === this.armedKey) {
          this.calls++
          // Call #2 is push's internal read; inject just before it observes state.
          if (this.calls === 2 && this.competing != null) {
            await super.put(key, this.competing, undefined, ctx)
            this.competing = null
            this.armedKey = null
          }
        }
        return super.getString(key, ctx)
      }
    }

    const store = new OneShotConflictStore(new Map())
    const { app } = makeRouter({ collections: sourceAndList(), projections: [catalogProjection], store })

    // Seed the list with one entry.
    await pushDoc(app, "/push/products/a", { name: "Alpha" })

    // Arm a competing write that adds entry "c" to the list, then push "b". The
    // plugin's first push will hash-mismatch, re-pull (now seeing "a" + "c") and
    // re-apply "b" on top — losing neither.
    store.arm(
      "catalog",
      JSON.stringify({
        v: 1,
        data: {
          items: [
            { id: "a", value: { name: "Alpha" } },
            { id: "c", value: { name: "Concurrent" } },
          ],
        },
        ts: 1,
        hash: "f".repeat(64),
      }),
    )

    await pushDoc(app, "/push/products/b", { name: "Beta" })

    // Both the concurrently-injected "c" and the retried "b" survive.
    expect(ids(await readList(store, "catalog"))).toEqual(["a", "c", "b"])
  })

  it("caps the list at maxItems, dropping further appends", async () => {
    const { app, store } = makeRouter({
      collections: sourceAndList(),
      projections: [catalogProjection],
      pluginOpts: { maxItems: 2 },
    })

    await pushDoc(app, "/push/products/a", { name: "A" })
    await pushDoc(app, "/push/products/b", { name: "B" })
    await pushDoc(app, "/push/products/c", { name: "C" }) // exceeds cap → dropped

    expect(ids(await readList(store, "catalog"))).toEqual(["a", "b"])
  })

  it("a pullOnly target list rejects direct client writes", async () => {
    const { app } = makeRouter({ collections: sourceAndList(), projections: [catalogProjection] })

    await pushDoc(app, "/push/products/a", { name: "Alpha" })
    expect((await app.request("/pull/catalog")).status).toBe(200) // projection populated it

    // …but a client cannot push to it directly (pullOnly → no push route).
    const res = await pushDoc(app, "/push/catalog", { tampered: true })
    expect(res.status).toBeGreaterThanOrEqual(400)
  })

  it("a projection failure does not break the originating client write", async () => {
    const { app } = makeRouter({
      collections: [jsonCol({ name: "products", storagePath: "products/{id}" })],
      projections: [
        {
          source: "products",
          target: "catalog",
          project: () => {
            throw new Error("boom")
          },
        },
      ],
    })

    const res = await pushDoc(app, "/push/products/a", { name: "x" })
    expect(res.status).toBe(200)
    expect((await res.json()).hash).toHaveLength(64)
  })
})
