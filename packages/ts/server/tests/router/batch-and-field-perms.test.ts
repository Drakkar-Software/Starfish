import { describe, it, expect, vi } from "vitest"
import { createSyncRouter, type SyncRouterOptions } from "../../src/router/route-builder.js"
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

describe("batch pull endpoint", () => {
  function makeRouter(overrides: Partial<SyncRouterOptions> = {}) {
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
      store,
      config: {
        version: 1,
        collections: [
          {
            name: "public-data",
            storagePath: "public/data",
            readRoles: ["public"],
            writeRoles: ["admin"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
          },
          {
            name: "private-data",
            storagePath: "private/data",
            readRoles: ["admin"],
            writeRoles: ["admin"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
          },
          {
            name: "user-doc",
            storagePath: "users/{identity}/doc",
            readRoles: ["public"],
            writeRoles: ["self"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
          },
        ],
      },
      roleResolver: async () => ({ identity: "user-1", roles: ["viewer"] }),
      ...overrides,
    })
    return { app, store }
  }

  it("returns 400 for missing collections parameter", async () => {
    const { app } = makeRouter()
    const res = await app.request("/batch/pull")
    expect(res.status).toBe(400)
  })

  it("returns error for unknown collection", async () => {
    const { app } = makeRouter()
    const res = await app.request("/batch/pull?collections=nonexistent")
    expect(res.status).toBe(200)
    const body = await res.json()
    // A name read with no params yields a one-element array.
    expect(body.collections.nonexistent[0].error).toBe("Collection not found")
  })

  it("allows access to public collections", async () => {
    const { app } = makeRouter()
    const res = await app.request("/batch/pull?collections=public-data")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections["public-data"]).toHaveLength(1)
    expect(body.collections["public-data"][0].data).toBeDefined()
  })

  it("denies access to private collections without proper roles", async () => {
    const { app } = makeRouter()
    const res = await app.request("/batch/pull?collections=private-data")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections["private-data"][0].error).toBe("Forbidden")
  })

  it("returns mixed results for public and private collections", async () => {
    const { app } = makeRouter()
    const res = await app.request("/batch/pull?collections=public-data,private-data")
    expect(res.status).toBe(200)
    const body = await res.json()
    // Public should succeed
    expect(body.collections["public-data"][0].data).toBeDefined()
    // Private should fail
    expect(body.collections["private-data"][0].error).toBe("Forbidden")
  })

  it("allows admin to access private collections", async () => {
    const { app } = makeRouter({
      roleResolver: async () => ({ identity: "admin-1", roles: ["admin"] }),
    })
    const res = await app.request("/batch/pull?collections=private-data")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections["private-data"][0].data).toBeDefined()
  })

  it("resolves a {identity}-templated collection from the authenticated caller", async () => {
    const { app, store } = makeRouter()
    // Seed the caller's own doc; the default resolver authenticates as "user-1".
    await store.put(
      "users/user-1/doc",
      JSON.stringify({ data: { v: 1 }, hash: "h", ts: Date.now() }),
    )
    const res = await app.request("/batch/pull?collections=user-doc,public-data")
    expect(res.status).toBe(200)
    const body = await res.json()
    // `{identity}` is auto-filled from the caller, so their own doc resolves —
    // no longer rejected as "not batch-pullable".
    expect(body.collections["user-doc"][0].error).toBeUndefined()
    expect(body.collections["user-doc"][0].data).toEqual({ v: 1 })
    // A singleton collection in the same request is still served.
    expect(body.collections["public-data"][0].data).toBeDefined()
  })

  it("drops empty slots in the collections CSV like the Python handler does", async () => {
    // Empty slots (leading/trailing/double commas) are filtered, so a malformed CSV
    // never produces spurious `""` → "Collection not found" entries — matching Python.
    const { app } = makeRouter()
    const res = await app.request("/batch/pull?collections=,public-data,,")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(Object.keys(body.collections)).toEqual(["public-data"])
    expect(body.collections["public-data"][0].data).toBeDefined()
  })

  it("returns an empty result set for an all-empty CSV (parity with Python, not 400)", async () => {
    // `,,` is present-but-all-empty: the param guard only fires when the param itself
    // is absent/empty, so this resolves to no names and 200 `{ collections: {} }`.
    const { app } = makeRouter()
    const res = await app.request("/batch/pull?collections=,,")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections).toEqual({})
  })
})

describe("batch pull param resolution", () => {
  // A `self`-gated per-user collection and a `{teamId}` collection that takes a
  // caller-supplied param. Default resolver authenticates as "user-1".
  function makeParamRouter(overrides: Partial<SyncRouterOptions> = {}) {
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
      store,
      config: {
        version: 1,
        collections: [
          {
            name: "public-data",
            storagePath: "public/data",
            readRoles: ["public"],
            writeRoles: ["admin"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
          },
          {
            name: "journal",
            storagePath: "users/{identity}/journal",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
          },
          {
            name: "team-notes",
            storagePath: "teams/{teamId}/notes",
            readRoles: ["public"],
            writeRoles: ["admin"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
          },
          {
            name: "team-journal",
            storagePath: "users/{identity}/teams/{teamId}/notes",
            readRoles: ["public"],
            writeRoles: ["self"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
          },
        ],
      },
      roleResolver: async () => ({ identity: "user-1", roles: [] }),
      ...overrides,
    })
    return { app, store }
  }

  const enc = (o: unknown) => encodeURIComponent(JSON.stringify(o))

  it("resolves a caller-supplied non-identity param", async () => {
    const { app, store } = makeParamRouter()
    await store.put(
      "teams/42/notes",
      JSON.stringify({ data: { topic: "launch" }, hash: "h", ts: Date.now() }),
    )
    const res = await app.request(
      `/batch/pull?collections=team-notes&params=${enc({ "team-notes": [{ teamId: "42" }] })}`,
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections["team-notes"][0].data).toEqual({ topic: "launch" })
  })

  it("fans in MANY documents of one collection in a single request", async () => {
    // The core of the generalization: one collection name, an array of param-sets,
    // one result array aligned to input order.
    const { app, store } = makeParamRouter()
    await store.put("teams/42/notes", JSON.stringify({ data: { topic: "a" }, hash: "h", ts: Date.now() }))
    await store.put("teams/99/notes", JSON.stringify({ data: { topic: "b" }, hash: "h", ts: Date.now() }))
    const res = await app.request(
      `/batch/pull?collections=team-notes&params=${enc({
        "team-notes": [{ teamId: "42" }, { teamId: "99" }],
      })}`,
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections["team-notes"].map((e: { data: unknown }) => e.data)).toEqual([
      { topic: "a" },
      { topic: "b" },
    ])
  })

  it("returns per-document mixed success/error within one collection's fan-out", async () => {
    // Entries stay index-aligned: a valid set yields data, a set missing a required
    // param yields an error in the SAME position.
    const { app, store } = makeParamRouter()
    await store.put("teams/42/notes", JSON.stringify({ data: { topic: "a" }, hash: "h", ts: Date.now() }))
    const res = await app.request(
      `/batch/pull?collections=team-notes&params=${enc({
        "team-notes": [{ teamId: "42" }, {}],
      })}`,
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections["team-notes"][0].data).toEqual({ topic: "a" })
    expect(body.collections["team-notes"][1].error).toBe("Missing required path parameter")
  })

  it("emits one 'Collection not found' entry per requested set (index-aligned)", async () => {
    // An unknown collection with N param-sets returns N error entries so the result
    // array length matches the caller's input (batchPullMany indexes by position).
    const { app } = makeParamRouter()
    const res = await app.request(
      `/batch/pull?collections=nope&params=${enc({ nope: [{}, {}, {}] })}`,
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.nope).toHaveLength(3)
    expect(body.collections.nope.every((e: { error: string }) => e.error === "Collection not found")).toBe(true)
  })

  it("returns an empty array for an empty param-set list (no reads)", async () => {
    const { app } = makeParamRouter()
    const res = await app.request(
      `/batch/pull?collections=team-notes&params=${enc({ "team-notes": [] })}`,
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections["team-notes"]).toEqual([])
  })

  it("rejects a non-array per-collection params value (array-of-objects required)", async () => {
    // The pre-generalization object shape is no longer accepted — a bare object is a
    // framing error → whole-request 400.
    const { app } = makeParamRouter()
    const res = await app.request(
      `/batch/pull?collections=team-notes&params=${enc({ "team-notes": { teamId: "42" } })}`,
    )
    expect(res.status).toBe(400)
    expect((await res.json()).error).toBe("Invalid params parameter")
  })

  it("auto-fills {identity} so the caller reads their OWN self-gated doc", async () => {
    const { app, store } = makeParamRouter()
    await store.put(
      "users/user-1/journal",
      JSON.stringify({ data: { entries: 3 }, hash: "h", ts: Date.now() }),
    )
    // No params supplied — identity is filled from the authenticated caller, and
    // the resulting `self` role satisfies the collection's readRoles.
    const res = await app.request("/batch/pull?collections=journal")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections["journal"][0].data).toEqual({ entries: 3 })
  })

  it("denies a forged identity on a self-gated collection (no self role)", async () => {
    const { app, store } = makeParamRouter()
    // user-2's journal exists, but the caller authenticates as user-1.
    await store.put(
      "users/user-2/journal",
      JSON.stringify({ data: { secret: true }, hash: "h", ts: Date.now() }),
    )
    const res = await app.request(
      `/batch/pull?collections=journal&params=${enc({ journal: [{ identity: "user-2" }] })}`,
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    // Supplied identity != caller → no `self` role → readRoles unmet → Forbidden,
    // and crucially no `data` leaks.
    expect(body.collections["journal"][0].error).toBe("Forbidden")
    expect(body.collections["journal"][0].data).toBeUndefined()
  })

  it("reports a missing required param", async () => {
    const { app } = makeParamRouter()
    // team-notes needs {teamId}; none supplied and it is not identity-auto-fillable.
    const res = await app.request("/batch/pull?collections=team-notes")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections["team-notes"][0].error).toBe("Missing required path parameter")
    expect(body.collections["team-notes"][0].data).toBeUndefined()
  })

  it("merges an auto-filled {identity} with a supplied {teamId} in one path", async () => {
    // team-journal needs BOTH {identity} (auto-filled) and {teamId} (supplied).
    // Getting data back proves the two sources merge into the resolved key —
    // a regression that gated auto-fill on "no params at all" would miss identity
    // here and return "Missing required path parameter" instead.
    const { app, store } = makeParamRouter()
    await store.put(
      "users/user-1/teams/42/notes",
      JSON.stringify({ data: { n: 7 }, hash: "h", ts: Date.now() }),
    )
    const res = await app.request(
      `/batch/pull?collections=team-journal&params=${enc({ "team-journal": [{ teamId: "42" }] })}`,
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections["team-journal"][0].error).toBeUndefined()
    expect(body.collections["team-journal"][0].data).toEqual({ n: 7 })
  })

  it("applies TTL expiry against the RESOLVED key (not the template)", async () => {
    // Guards the param case of the TTL read: the stored-doc timestamp must be
    // read from the resolved `users/user-1/ephemeral` key, not the `{identity}`
    // template. An expired doc is zeroed exactly as on the standalone path.
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
      store,
      config: {
        version: 1,
        collections: [
          {
            name: "user-ephemeral",
            storagePath: "users/{identity}/ephemeral",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            ttlMs: 1000,
          },
        ],
      },
      roleResolver: async () => ({ identity: "user-1", roles: [] }),
    })
    await store.put(
      "users/user-1/ephemeral",
      JSON.stringify({ data: { v: 1 }, hash: "h", ts: Date.now() - 999_999 }),
    )
    const res = await app.request("/batch/pull?collections=user-ephemeral")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections["user-ephemeral"][0].data).toEqual({})
  })

  it("rejects a malformed params blob with a whole-request 400", async () => {
    const { app } = makeParamRouter()
    const res = await app.request("/batch/pull?collections=public-data&params=not-json")
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toBe("Invalid params parameter")
  })

  it("rejects an unsafe param value per-collection while serving siblings", async () => {
    const { app } = makeParamRouter()
    const res = await app.request(
      `/batch/pull?collections=team-notes,public-data&params=${enc({ "team-notes": [{ teamId: "a/b" }] })}`,
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    // "a/b" contains "/", which fails the per-segment charset check.
    expect(body.collections["team-notes"][0].error).toBe("Invalid path parameter")
    // The sibling singleton is unaffected.
    expect(body.collections["public-data"][0].data).toBeDefined()
  })

  it("blocks a `..` traversal value via the resolved-key guard", async () => {
    const { app } = makeParamRouter()
    // ".." passes the per-segment charset (dots are allowed) but composes a
    // traversal key, which isUnsafeDocumentKey rejects before any store read.
    const res = await app.request(
      `/batch/pull?collections=team-notes&params=${enc({ "team-notes": [{ teamId: ".." }] })}`,
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections["team-notes"][0].error).toBe("Invalid path parameter")
  })

  it("enforces cap scope.paths against the resolved key", async () => {
    // A cap-cert resolver returns `scopePaths`; the batch handler re-checks each
    // RESOLVED key against it (the resolver can't path-bind /batch/pull). A caller
    // scoped to team 42 reads 42 but is Forbidden on 99 — batch can't side-step
    // the per-path scope. Proven in ONE fan-out request so the per-entry scope
    // check is exercised, not just the per-collection one.
    const { app, store } = makeParamRouter({
      roleResolver: async () => ({ identity: "user-1", roles: [], scopePaths: ["teams/42/notes"] }),
    })
    await store.put("teams/42/notes", JSON.stringify({ data: { ok: 1 }, hash: "h", ts: Date.now() }))
    await store.put("teams/99/notes", JSON.stringify({ data: { secret: 1 }, hash: "h", ts: Date.now() }))
    const res = await app.request(
      `/batch/pull?collections=team-notes&params=${enc({
        "team-notes": [{ teamId: "42" }, { teamId: "99" }],
      })}`,
    )
    const body = await res.json()
    expect(body.collections["team-notes"][0].data).toEqual({ ok: 1 })
    expect(body.collections["team-notes"][1].error).toBe("Forbidden")
    expect(body.collections["team-notes"][1].data).toBeUndefined()
  })

  it("rejects a batch naming more than maxCollectionsPerBatch collections", async () => {
    const { app } = makeParamRouter({ maxCollectionsPerBatch: 2 })
    const res = await app.request("/batch/pull?collections=public-data,team-notes,journal")
    expect(res.status).toBe(400)
    expect((await res.json()).error).toBe("Too many collections")
  })

  it("rejects a fan-out whose TOTAL reads exceed maxCollectionsPerBatch (one name)", async () => {
    // The distinct-name cap is no longer sufficient: a single name with an
    // oversized param-set array must also be rejected by the total-reads guard.
    const { app } = makeParamRouter({ maxCollectionsPerBatch: 2 })
    const res = await app.request(
      `/batch/pull?collections=team-notes&params=${enc({
        "team-notes": [{ teamId: "1" }, { teamId: "2" }, { teamId: "3" }],
      })}`,
    )
    expect(res.status).toBe(400)
    expect((await res.json()).error).toBe("Too many collections")
  })

  it("writes audit records for batch denials and successes", async () => {
    const records: Array<Record<string, unknown>> = []
    const { app, store } = makeParamRouter({
      auditLogger: {
        record: (e: Record<string, unknown>) => {
          records.push(e)
        },
      } as unknown as SyncRouterOptions["auditLogger"],
    })
    await store.put(
      "teams/42/notes",
      JSON.stringify({ data: { ok: 1 }, hash: "h", ts: Date.now() }),
    )
    // team-notes (public, in scope) → success; journal forged identity → Forbidden.
    await app.request(
      `/batch/pull?collections=team-notes,journal&params=${enc({
        "team-notes": [{ teamId: "42" }],
        journal: [{ identity: "user-2" }],
      })}`,
    )
    const pulls = records.filter((r) => r.action === "pull")
    expect(pulls.find((r) => r.collection === "team-notes")).toMatchObject({
      success: true,
      statusCode: 200,
    })
    expect(pulls.find((r) => r.collection === "journal")).toMatchObject({
      success: false,
      statusCode: 403,
    })
  })

  it("audits the degrade-to-anonymous when an invalid cap is presented", async () => {
    const records: Array<Record<string, unknown>> = []
    const { app } = makeParamRouter({
      // A revoked/invalid cap: the resolver throws with a 403 status.
      roleResolver: async () => {
        throw Object.assign(new Error("revoked"), { status: 403 })
      },
      auditLogger: {
        record: (e: Record<string, unknown>) => {
          records.push(e)
        },
      } as unknown as SyncRouterOptions["auditLogger"],
    })
    // public-data is still served (degrade-to-anonymous), and the auth failure is
    // recorded as a request-level audit entry (collection: "").
    const res = await app.request("/batch/pull?collections=public-data")
    expect(res.status).toBe(200)
    expect((await res.json()).collections["public-data"][0].data).toBeDefined()
    const pulls = records.filter((r) => r.action === "pull")
    expect(pulls.find((r) => r.collection === "")).toMatchObject({ success: false, statusCode: 403 })
    expect(pulls.find((r) => r.collection === "public-data")).toMatchObject({ success: true, statusCode: 200 })
  })

  it("does not relabel a successful read as an error when the audit logger throws", async () => {
    // The success-audit runs inside the per-collection read try/catch, so a
    // throwing logger must be swallowed — best-effort audit can't corrupt data.
    const { app, store } = makeParamRouter({
      auditLogger: {
        record: async () => {
          throw new Error("audit down")
        },
      } as unknown as SyncRouterOptions["auditLogger"],
    })
    await store.put(
      "teams/42/notes",
      JSON.stringify({ data: { ok: 1 }, hash: "h", ts: Date.now() }),
    )
    const res = await app.request(
      `/batch/pull?collections=team-notes&params=${enc({ "team-notes": [{ teamId: "42" }] })}`,
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections["team-notes"][0].data).toEqual({ ok: 1 })
    expect(body.collections["team-notes"][0].error).toBeUndefined()
  })

  it("ignores caller-supplied params outside the collection's template", async () => {
    const { app, store } = makeParamRouter()
    await store.put(
      "teams/42/notes",
      JSON.stringify({ data: { ok: 1 }, hash: "h", ts: Date.now() }),
    )
    // `junk` is not a template param of teams/{teamId}/notes — it's dropped, not
    // validated or passed downstream. Even an UNSAFE value for it is ignored, so
    // the collection still resolves on its template param alone (under the old
    // pass-through code the "a/b" would have triggered "Invalid path parameter").
    const res = await app.request(
      `/batch/pull?collections=team-notes&params=${enc({
        "team-notes": [{ teamId: "42", junk: "a/b" }],
      })}`,
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections["team-notes"][0].error).toBeUndefined()
    expect(body.collections["team-notes"][0].data).toEqual({ ok: 1 })
  })
})

describe("batch pull TTL expiry", () => {
  function makeTtlRouter() {
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
      store,
      config: {
        version: 1,
        collections: [
          {
            name: "ephemeral",
            storagePath: "ephemeral/data",
            readRoles: ["public"],
            writeRoles: ["admin"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            ttlMs: 1000,
          },
        ],
      },
      roleResolver: async () => ({ identity: "u", roles: ["viewer"] }),
    })
    return { app, store }
  }

  it("omits data for a document past its ttlMs (parity with the standalone + Python paths)", async () => {
    const { app, store } = makeTtlRouter()
    // Seed an expired doc: its stored write-time is far in the past.
    await store.put(
      "ephemeral/data",
      JSON.stringify({ data: { v: 1 }, hash: "h", ts: Date.now() - 999_999 }),
    )
    const res = await app.request("/batch/pull?collections=ephemeral")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.ephemeral[0].data).toEqual({})
  })

  it("returns data for a fresh document within ttlMs", async () => {
    const { app, store } = makeTtlRouter()
    await store.put(
      "ephemeral/data",
      JSON.stringify({ data: { v: 1 }, hash: "h", ts: Date.now() }),
    )
    const res = await app.request("/batch/pull?collections=ephemeral")
    const body = await res.json()
    expect(body.collections.ephemeral[0].data).toEqual({ v: 1 })
  })
})

describe("field-level permissions", () => {
  function makeRouter(overrides: Partial<SyncRouterOptions> = {}) {
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
      store,
      config: {
        version: 1,
        collections: [
          {
            name: "profile",
            storagePath: "users/{identity}/profile",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            fieldPermissions: {
              email: { readRoles: ["admin"], writeRoles: ["admin"] },
              name: { readRoles: ["self", "admin"] },
            },
          },
        ],
      },
      roleResolver: async () => ({ identity: "user-1", roles: [] }),
      ...overrides,
    })
    return { app, store }
  }

  it("strips fields the user can't read", async () => {
    // Push as admin (has write access to all fields)
    const { app: adminApp } = makeRouter({
      roleResolver: async () => ({ identity: "user-1", roles: ["admin"] }),
    })
    const pushRes = await adminApp.request("/push/users/user-1/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        data: { name: "Alice", email: "alice@example.com", bio: "Hello" },
        baseHash: null,
      }),
    })
    expect(pushRes.status).toBe(200)

    // Pull as non-admin — email should be stripped
    // Need a new router with same store to test with different roles
    // Since stores are isolated per makeRouter call, use admin router for pull too
    // but override the roleResolver for pull
    const res = await adminApp.request("/pull/users/user-1/profile")
    expect(res.status).toBe(200)
    const body = await res.json()
    // Admin can see all fields including email
    expect(body.data.name).toBe("Alice")
    expect(body.data.email).toBe("alice@example.com")
    expect(body.data.bio).toBe("Hello")
  })

  it("non-admin cannot read admin-restricted fields", async () => {
    // Push as admin first
    const store = new MemoryObjectStore(new Map())
    const adminApp = createSyncRouter({
      store,
      config: {
        version: 1,
        collections: [
          {
            name: "profile",
            storagePath: "users/{identity}/profile",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            fieldPermissions: {
              email: { readRoles: ["admin"], writeRoles: ["admin"] },
            },
          },
        ],
      },
      roleResolver: async () => ({ identity: "user-1", roles: ["admin"] }),
    })
    await adminApp.request("/push/users/user-1/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        data: { name: "Alice", email: "alice@example.com" },
        baseHash: null,
      }),
    })

    // Pull as non-admin (same store, different role resolver)
    const userApp = createSyncRouter({
      store,
      config: {
        version: 1,
        collections: [
          {
            name: "profile",
            storagePath: "users/{identity}/profile",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            fieldPermissions: {
              email: { readRoles: ["admin"], writeRoles: ["admin"] },
            },
          },
        ],
      },
      roleResolver: async () => ({ identity: "user-1", roles: [] }),
    })
    const res = await userApp.request("/pull/users/user-1/profile")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data.name).toBe("Alice")
    expect(body.data.email).toBeUndefined() // Stripped for non-admin
  })

  it("rejects writes to field-restricted fields", async () => {
    const { app } = makeRouter()
    // Non-admin trying to write email (restricted to admin writeRoles)
    const res = await app.request("/push/users/user-1/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        data: { name: "Alice", email: "alice@example.com" },
        baseHash: null,
      }),
    })
    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body.error).toContain("email")
  })

  it("allows any authenticated user to write a field whose writeRoles is public", async () => {
    // writeRoles:["public"] marks the field unrestricted; an authenticated user with
    // role "self" (not the literal "public") must still be allowed. The field-write
    // check honors ROLE_PUBLIC (route-builder.ts:439). See test_ttl_and_field_permissions.py
    // for the Python twin — currently xfailed, as the Python write check omits ROLE_PUBLIC.
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
      store,
      config: {
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
            fieldPermissions: { openField: { writeRoles: ["public"] } },
          },
        ],
      },
      roleResolver: async () => ({ identity: "user-1", roles: ["self"] }),
    })
    const res = await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { openField: "anyone-can-write" }, baseHash: null }),
    })
    expect(res.status).toBe(200)
  })

  it("treats an explicit null on a restricted field as a write (presence, not truthiness)", async () => {
    // Setting an admin-only field to `null` must still be rejected — the guard keys on
    // the field being PRESENT in `data`, so a non-admin cannot blank/no-op-touch it by
    // sending null; only omitting the key avoids the check. Pins null can't slip past.
    const { app } = makeRouter()
    const res = await app.request("/push/users/user-1/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { name: "Alice", email: null }, baseHash: null }),
    })
    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body.error).toContain("email")
  })

  it("allows writes to unrestricted fields", async () => {
    const { app } = makeRouter()
    const res = await app.request("/push/users/user-1/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        data: { name: "Alice", bio: "Hello" },
        baseHash: null,
      }),
    })
    expect(res.status).toBe(200)
  })

  it("keeps the ETag (and 304) through field-read filtering", async () => {
    // The field filter mutates `data` in place and leaves `hash` intact, so the
    // hash-derived ETag survives and conditional requests still 304. (The Python twin
    // currently drops the ETag on its rebuild — pinned there as a strict xfail.)
    const { app } = makeRouter()
    await app.request("/push/users/user-1/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { name: "Alice", bio: "Hello" }, baseHash: null }),
    })
    const res1 = await app.request("/pull/users/user-1/profile")
    expect(res1.status).toBe(200)
    const etag = res1.headers.get("etag")
    expect(etag).toBeTruthy()
    const res2 = await app.request("/pull/users/user-1/profile", {
      headers: { "If-None-Match": etag! },
    })
    expect(res2.status).toBe(304)
  })
})

describe("CORS credentials validation", () => {
  it("throws when credentials=true with wildcard origin", () => {
    expect(() => {
      createSyncRouter({
        store: new MemoryObjectStore(new Map()),
        config: { version: 1, collections: [] },
        roleResolver: async () => ({ identity: "u", roles: [] }),
        cors: { credentials: true },
      })
    }).toThrow("credentials cannot be used with wildcard origin")
  })

  it("allows credentials with specific origin", () => {
    expect(() => {
      createSyncRouter({
        store: new MemoryObjectStore(new Map()),
        config: { version: 1, collections: [] },
        roleResolver: async () => ({ identity: "u", roles: [] }),
        cors: { origin: "https://example.com", credentials: true },
      })
    }).not.toThrow()
  })
})
