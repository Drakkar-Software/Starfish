import { describe, it, expect, vi, beforeEach } from "vitest"
import { webcrypto } from "node:crypto"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { createEntitlementRoleEnricher } from "../../src/enrichers/entitlement-role-enricher.js"
import { composeEnrichers } from "../../src/enrichers/compose.js"
import { createGroupRoleEnricher } from "../../src/enrichers/group-role-enricher.js"
import { createSyncRouter, type SyncRouterOptions, type AuthResult } from "../../src/router/route-builder.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import type { SyncConfig, CollectionConfig } from "../../src/config/schema.js"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

// ── Helpers ───────────────────────────────────────────────────────────────────

async function writeEntitlementDoc(
  store: MemoryObjectStore,
  key: string,
  features: string[],
) {
  const doc = {
    v: 1,
    data: { features },
    timestamps: { features: Date.now() },
    hash: "test-hash",
  }
  await store.put(key, JSON.stringify(doc))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

describe("createEntitlementRoleEnricher — unit", () => {
  it("grants roles for all feature slugs in the document", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeEntitlementDoc(store, "users/alice/entitlements", ["premium-package-1", "paid-cloud-sync"])

    const enricher = createEntitlementRoleEnricher({ store })

    const roles = await enricher({ identity: "alice", roles: [] }, {})
    expect(roles.sort()).toEqual(["entitlement:paid-cloud-sync", "entitlement:premium-package-1"])
  })

  it("returns empty array when entitlement document is missing", async () => {
    const store = new MemoryObjectStore(new Map())
    const enricher = createEntitlementRoleEnricher({ store })

    const roles = await enricher({ identity: "alice", roles: [] }, {})
    expect(roles).toEqual([])
  })

  it("returns empty array when document is corrupt JSON", async () => {
    const store = new MemoryObjectStore(new Map())
    await store.put("users/alice/entitlements", "not valid json{{")

    const enricher = createEntitlementRoleEnricher({ store })
    const roles = await enricher({ identity: "alice", roles: [] }, {})
    expect(roles).toEqual([])
  })

  it("returns empty array when features field is not an array", async () => {
    const store = new MemoryObjectStore(new Map())
    const doc = { v: 1, data: { features: "not-a-list" }, timestamps: {}, hash: "h" }
    await store.put("users/alice/entitlements", JSON.stringify(doc))

    const enricher = createEntitlementRoleEnricher({ store })
    const roles = await enricher({ identity: "alice", roles: [] }, {})
    expect(roles).toEqual([])
  })

  it("filters non-string elements from the features list", async () => {
    const store = new MemoryObjectStore(new Map())
    const doc = { v: 1, data: { features: ["valid-feature", 42, null, true] }, timestamps: {}, hash: "h" }
    await store.put("users/alice/entitlements", JSON.stringify(doc))

    const enricher = createEntitlementRoleEnricher({ store })
    const roles = await enricher({ identity: "alice", roles: [] }, {})
    expect(roles).toEqual(["entitlement:valid-feature"])
  })

  it("respects custom field option", async () => {
    const store = new MemoryObjectStore(new Map())
    const doc = { v: 1, data: { entitlements: ["pro"] }, timestamps: {}, hash: "h" }
    await store.put("users/alice/entitlements", JSON.stringify(doc))

    const enricher = createEntitlementRoleEnricher({ store, field: "entitlements" })
    const roles = await enricher({ identity: "alice", roles: [] }, {})
    expect(roles).toEqual(["entitlement:pro"])
  })

  it("respects custom rolePrefix option", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeEntitlementDoc(store, "users/alice/entitlements", ["premium"])

    const enricher = createEntitlementRoleEnricher({ store, rolePrefix: "feat" })
    const roles = await enricher({ identity: "alice", roles: [] }, {})
    expect(roles).toEqual(["feat:premium"])
  })

  it("respects custom path template option", async () => {
    const store = new MemoryObjectStore(new Map())
    const doc = { v: 1, data: { features: ["pro"] }, timestamps: {}, hash: "h" }
    await store.put("ents/alice", JSON.stringify(doc))

    const enricher = createEntitlementRoleEnricher({ store, path: "ents/{identity}" })
    const roles = await enricher({ identity: "alice", roles: [] }, {})
    expect(roles).toEqual(["entitlement:pro"])
  })

  it("uses auth.identity as the lookup key, ignores URL params", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeEntitlementDoc(store, "users/alice/entitlements", ["premium"])

    const enricher = createEntitlementRoleEnricher({ store })
    // Pass URL params that have nothing to do with the identity
    const roles = await enricher(
      { identity: "alice", roles: [] },
      { groupId: "group-42", someOther: "value" },
    )
    expect(roles).toEqual(["entitlement:premium"])
  })

  it("caches entitlement lookups within TTL", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeEntitlementDoc(store, "users/alice/entitlements", ["premium"])

    const getStringSpy = vi.spyOn(store, "getString")
    const enricher = createEntitlementRoleEnricher({ store, cacheTtlMs: 60_000 })

    await enricher({ identity: "alice", roles: [] }, {})
    await enricher({ identity: "alice", roles: [] }, {})

    // getString called only once — second call served from cache
    expect(getStringSpy).toHaveBeenCalledTimes(1)
  })

  it("different identities have separate cache entries", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeEntitlementDoc(store, "users/alice/entitlements", ["premium"])
    await writeEntitlementDoc(store, "users/bob/entitlements", ["basic"])

    const getStringSpy = vi.spyOn(store, "getString")
    const enricher = createEntitlementRoleEnricher({ store, cacheTtlMs: 60_000 })

    await enricher({ identity: "alice", roles: [] }, {})
    await enricher({ identity: "bob", roles: [] }, {})
    await enricher({ identity: "alice", roles: [] }, {}) // served from cache
    await enricher({ identity: "bob", roles: [] }, {})   // served from cache

    // One read per distinct identity
    expect(getStringSpy).toHaveBeenCalledTimes(2)
  })

  it("bypasses cache when cacheTtlMs is 0", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeEntitlementDoc(store, "users/alice/entitlements", ["premium"])

    const getStringSpy = vi.spyOn(store, "getString")
    const enricher = createEntitlementRoleEnricher({ store, cacheTtlMs: 0 })

    await enricher({ identity: "alice", roles: [] }, {})
    await enricher({ identity: "alice", roles: [] }, {})

    expect(getStringSpy).toHaveBeenCalledTimes(2)
  })

  it("cache expires and re-reads after TTL", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeEntitlementDoc(store, "users/alice/entitlements", ["premium"])

    const getStringSpy = vi.spyOn(store, "getString")
    const enricher = createEntitlementRoleEnricher({ store, cacheTtlMs: 5_000 })

    const nowSpy = vi.spyOn(Date, "now")
    // Call 1 at t=0
    nowSpy.mockReturnValueOnce(0)
    await enricher({ identity: "alice", roles: [] }, {})
    expect(getStringSpy).toHaveBeenCalledTimes(1)

    // Call 2 at t=4999 — within TTL
    nowSpy.mockReturnValueOnce(4_999)
    await enricher({ identity: "alice", roles: [] }, {})
    expect(getStringSpy).toHaveBeenCalledTimes(1)

    // Call 3 at t=5001 — TTL elapsed, re-reads
    nowSpy.mockReturnValueOnce(5_001)
    await enricher({ identity: "alice", roles: [] }, {})
    expect(getStringSpy).toHaveBeenCalledTimes(2)
  })
})

// ── composeEnrichers unit tests ───────────────────────────────────────────────

describe("composeEnrichers", () => {
  it("merges roles from multiple enrichers", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeEntitlementDoc(store, "users/alice/entitlements", ["premium"])

    const membersDoc = {
      v: 1,
      data: { members: ["alice"] },
      timestamps: { members: Date.now() },
      hash: "h",
    }
    await store.put("groups/g1/members", JSON.stringify(membersDoc))

    const groupEnricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
    })
    const entitlementEnricher = createEntitlementRoleEnricher({ store })

    const composed = composeEnrichers(groupEnricher, entitlementEnricher)
    const roles = await composed({ identity: "alice", roles: [] }, { groupId: "g1" })

    expect(roles).toContain("group-member")
    expect(roles).toContain("entitlement:premium")
  })

  it("returns empty array when no enrichers are provided", async () => {
    const composed = composeEnrichers()
    const roles = await composed({ identity: "alice", roles: [] }, {})
    expect(roles).toEqual([])
  })
})

// ── Integration tests through the router ─────────────────────────────────────

describe("createEntitlementRoleEnricher — integration via router", () => {
  function makeIntegrationSetup(identity: string, baseRoles: string[] = []) {
    const store = new MemoryObjectStore(new Map())

    const entitlementsCol: CollectionConfig = {
      name: "entitlements",
      storagePath: "users/{identity}/entitlements",
      readRoles: ["self"],
      writeRoles: ["admin"],
      encryption: "none",
      maxBodyBytes: 4096,
      allowedMimeTypes: ["application/json"],
    }
    const premiumCol: CollectionConfig = {
      name: "premium-data",
      storagePath: "premium/{resource}",
      readRoles: ["entitlement:premium-package-1"],
      writeRoles: ["admin"],
      encryption: "none",
      maxBodyBytes: 65536,
      allowedMimeTypes: ["application/json"],
    }

    const enricher = createEntitlementRoleEnricher({ store })
    const config: SyncConfig = { version: 1, collections: [entitlementsCol, premiumCol] }
    const opts: SyncRouterOptions = {
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({ identity, roles: baseRoles }),
      roleEnricher: enricher,
    }
    return { app: createSyncRouter(opts), store }
  }

  it("user with matching entitlement can pull a gated collection", async () => {
    const { app, store } = makeIntegrationSetup("alice")

    await writeEntitlementDoc(store, "users/alice/entitlements", ["premium-package-1"])

    const premiumDoc = {
      v: 1,
      data: { content: "secret data" },
      timestamps: { content: Date.now() },
      hash: "h",
    }
    await store.put("premium/article-1", JSON.stringify(premiumDoc))

    const res = await app.request("/pull/premium/article-1")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data.content).toBe("secret data")
  })

  it("user without entitlement gets 403", async () => {
    const { app, store } = makeIntegrationSetup("alice")

    await writeEntitlementDoc(store, "users/alice/entitlements", ["basic-tier"])

    const res = await app.request("/pull/premium/article-1")
    expect(res.status).toBe(403)
  })

  it("user with no entitlement document gets 403", async () => {
    const { app } = makeIntegrationSetup("alice")

    const res = await app.request("/pull/premium/article-1")
    expect(res.status).toBe(403)
  })

  it("user can read their own entitlement document via self role", async () => {
    const { app, store } = makeIntegrationSetup("alice")

    await writeEntitlementDoc(store, "users/alice/entitlements", ["premium-package-1"])

    const res = await app.request("/pull/users/alice/entitlements")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data.features).toContain("premium-package-1")
  })

  it("composeEnrichers: group + entitlement enrichers both applied", async () => {
    const store = new MemoryObjectStore(new Map())

    const membersDoc = {
      v: 1,
      data: { members: ["alice"] },
      timestamps: { members: Date.now() },
      hash: "h",
    }
    await store.put("groups/g1/members", JSON.stringify(membersDoc))
    await writeEntitlementDoc(store, "users/alice/entitlements", ["premium-package-1"])

    const col: CollectionConfig = {
      name: "combined",
      storagePath: "combined/{groupId}/{resource}",
      readRoles: ["group-member", "entitlement:premium-package-1"],
      writeRoles: ["admin"],
      encryption: "none",
      maxBodyBytes: 65536,
      allowedMimeTypes: ["application/json"],
    }
    const doc = { v: 1, data: { x: 1 }, timestamps: { x: Date.now() }, hash: "h" }
    await store.put("combined/g1/thing", JSON.stringify(doc))

    const config: SyncConfig = { version: 1, collections: [col] }
    const app = createSyncRouter({
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({ identity: "alice", roles: [] }),
      roleEnricher: composeEnrichers(
        createGroupRoleEnricher({ store, membersPath: "groups/{groupId}/members", groupParam: "groupId" }),
        createEntitlementRoleEnricher({ store }),
      ),
    })

    const res = await app.request("/pull/combined/g1/thing")
    expect(res.status).toBe(200)
  })
})
