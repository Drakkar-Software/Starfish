/**
 * Cross-space batch pull tests.
 *
 * Tests that /batch/pull authorises each requested collection entry
 * independently via the per-entry role enricher (simulating the spaces
 * `_access` registry) rather than requiring a per-space cap per request.
 *
 * Key invariants tested:
 *  - member reads own space, gets Forbidden for sibling → per-entry auth
 *  - owner reads all owned spaces → correct multi-space fan-out
 *  - stranger gets Forbidden for every space
 *  - per-space-cap (scope: "spaces/space-A/**") still blocks siblings (scope regression)
 *  - strict-TOFU (absent _access doc) → Forbidden, not 200-empty
 *  - empty param-set array → empty result (no reads, no auth round-trips)
 */
import { describe, it, expect } from "vitest"
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

// ── helpers ───────────────────────────────────────────────────────────────────

/** Build and seed a router with deterministic space _access docs. */
function makeRouter(
  callerIdentity: string,
  callerRoles: string[],
  scopePaths?: string[],
  overrides: Partial<SyncRouterOptions> = {},
) {
  const raw = new Map<string, string>([
    [
      "spaces/space-A/_access",
      JSON.stringify({
        data: { owner: "alice", members: ["alice", "bob"], name: "Alpha" },
        hash: "hash-A",
        ts: 1000,
      }),
    ],
    [
      "spaces/space-B/_access",
      JSON.stringify({
        data: { owner: "alice", members: ["alice"], name: "Beta" },
        hash: "hash-B",
        ts: 2000,
      }),
    ],
    [
      "spaces/space-C/_access",
      JSON.stringify({
        data: { owner: "carol", members: ["carol"], name: "Gamma" },
        hash: "hash-C",
        ts: 3000,
      }),
    ],
  ])
  const store = new MemoryObjectStore(raw)

  // Simulates createSpacesRoleEnricher with allowTofu:false (the default):
  // reads spaces/{spaceId}/_access from the store closure, grants space:member
  // and space:owner. Absent doc → no roles granted (no TOFU).
  // RoleEnricher signature: (auth: AuthResult, params) => Promise<string[]>
  const enricher = async (
    auth: { identity: string; roles: string[] },
    params: Record<string, string>,
  ): Promise<string[]> => {
    const identity = auth.identity
    const spaceId = params["spaceId"]
    if (!spaceId) return []
    const rawDoc = await store.getString(`spaces/${spaceId}/_access`)
    if (!rawDoc) return []           // allowTofu:false — absent = no roles
    let doc: any
    try { doc = JSON.parse(rawDoc) } catch { return [] }
    const data = doc.data ?? {}
    const owner: string | undefined = data.owner
    const members: string[] = Array.isArray(data.members) ? data.members : []
    const roles: string[] = []
    if (identity === owner) roles.push("space:owner")
    if (identity === owner || members.includes(identity)) roles.push("space:member")
    return roles
  }

  const app = createSyncRouter({
    store,
    config: {
      version: 1,
      collections: [
        {
          name: "spaceaccess",
          storagePath: "spaces/{spaceId}/_access",
          readRoles: ["space:member"],
          writeRoles: ["space:owner"],
          encryption: "none",
          maxBodyBytes: 64 * 1024,
          allowedMimeTypes: ["application/json"],
        },
      ],
    },
    roleResolver: async () => ({
      identity: callerIdentity,
      roles: callerRoles,
      scopePaths,
    }),
    roleEnricher: enricher,
    ...overrides,
  })

  return { app, store }
}

function params(obj: Record<string, Record<string, string>[]>) {
  return `params=${encodeURIComponent(JSON.stringify(obj))}`
}

// ── tests ─────────────────────────────────────────────────────────────────────

describe("cross-space batch pull — per-entry membership authorization", () => {
  it("member reads own space, gets Forbidden for sibling (per-entry auth)", async () => {
    const { app } = makeRouter("bob", [])
    const url = `/batch/pull?collections=spaceaccess&${params({
      spaceaccess: [{ spaceId: "space-A" }, { spaceId: "space-B" }],
    })}`
    const res = await app.request(url)
    expect(res.status).toBe(200)
    const body = await res.json()
    const entries = body.collections.spaceaccess
    // space-A: bob is a member → ok
    expect(entries[0].error).toBeUndefined()
    expect(entries[0].data?.name).toBe("Alpha")
    // space-B: bob is NOT a member → Forbidden
    expect(entries[1].error).toBe("Forbidden")
    expect(entries[1].data).toBeUndefined()
  })

  it("owner reads all owned spaces", async () => {
    const { app } = makeRouter("alice", [])
    const url = `/batch/pull?collections=spaceaccess&${params({
      spaceaccess: [{ spaceId: "space-A" }, { spaceId: "space-B" }],
    })}`
    const res = await app.request(url)
    expect(res.status).toBe(200)
    const body = await res.json()
    const entries = body.collections.spaceaccess
    expect(entries[0].error).toBeUndefined()
    expect(entries[0].data?.owner).toBe("alice")
    expect(entries[1].error).toBeUndefined()
    expect(entries[1].data?.owner).toBe("alice")
  })

  it("stranger gets Forbidden for every space", async () => {
    const { app } = makeRouter("dave", [])
    const url = `/batch/pull?collections=spaceaccess&${params({
      spaceaccess: [
        { spaceId: "space-A" },
        { spaceId: "space-B" },
        { spaceId: "space-C" },
      ],
    })}`
    const res = await app.request(url)
    expect(res.status).toBe(200)
    const body = await res.json()
    for (const entry of body.collections.spaceaccess) {
      expect(entry.error).toBe("Forbidden")
    }
  })

  it("per-space-scoped cap still blocks siblings (scope regression)", async () => {
    // scopePaths = ["spaces/space-A/**"] — matchScopePath must block space-B
    // even though alice is a member of both.
    const { app } = makeRouter("alice", [], ["spaces/space-A/**"])
    const url = `/batch/pull?collections=spaceaccess&${params({
      spaceaccess: [{ spaceId: "space-A" }, { spaceId: "space-B" }],
    })}`
    const res = await app.request(url)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.spaceaccess[0].error).toBeUndefined() // space-A ok
    expect(body.collections.spaceaccess[1].error).toBe("Forbidden") // scope-blocked
  })

  it("strict-TOFU: absent _access doc is Forbidden, not a 200 with empty data", async () => {
    // space-MISSING has no fixture → enricher returns [] → Forbidden.
    const { app } = makeRouter("alice", [])
    const url = `/batch/pull?collections=spaceaccess&${params({
      spaceaccess: [{ spaceId: "space-MISSING" }],
    })}`
    const res = await app.request(url)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.spaceaccess[0].error).toBe("Forbidden")
    // Must NOT be an empty 200 data object (that's the TOFU-open path).
    expect(body.collections.spaceaccess[0].data).toBeUndefined()
  })

  it("mixed: own space ok, absent space Forbidden, unjoined space Forbidden", async () => {
    const { app } = makeRouter("alice", [])
    const url = `/batch/pull?collections=spaceaccess&${params({
      spaceaccess: [
        { spaceId: "space-A" },       // alice is owner → ok
        { spaceId: "space-MISSING" }, // absent doc → Forbidden (no TOFU)
        { spaceId: "space-C" },       // carol's space → Forbidden
      ],
    })}`
    const res = await app.request(url)
    expect(res.status).toBe(200)
    const body = await res.json()
    const entries = body.collections.spaceaccess
    expect(entries[0].error).toBeUndefined()
    expect(entries[0].data?.owner).toBe("alice")
    expect(entries[1].error).toBe("Forbidden")
    expect(entries[2].error).toBe("Forbidden")
  })

  it("empty param-set array → empty result (no reads)", async () => {
    const { app } = makeRouter("alice", [])
    const url = `/batch/pull?collections=spaceaccess&${params({ spaceaccess: [] })}`
    const res = await app.request(url)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.spaceaccess).toEqual([])
  })

  it("collection not found returns per-entry errors aligned to param count", async () => {
    const { app } = makeRouter("alice", [])
    const url = `/batch/pull?collections=nonexistent&${params({
      nonexistent: [{ spaceId: "space-A" }, { spaceId: "space-B" }],
    })}`
    const res = await app.request(url)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.nonexistent).toHaveLength(2)
    for (const entry of body.collections.nonexistent) {
      expect(entry.error).toBe("Collection not found")
    }
  })

  it("path traversal in spaceId is rejected (Invalid path parameter or Forbidden)", async () => {
    const { app } = makeRouter("alice", [])
    const url = `/batch/pull?collections=spaceaccess&${params({
      spaceaccess: [{ spaceId: "../../../etc/passwd" }],
    })}`
    const res = await app.request(url)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.spaceaccess[0].error).toMatch(/Invalid path parameter|Forbidden/)
  })

  it("duplicate collection names are de-duplicated (one result array, not two)", async () => {
    const { app } = makeRouter("alice", [])
    const res = await app.request(
      `/batch/pull?collections=spaceaccess,spaceaccess&${params({
        spaceaccess: [{ spaceId: "space-A" }],
      })}`,
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    // De-dup: "spaceaccess" appears exactly once
    expect(Object.keys(body.collections)).toEqual(["spaceaccess"])
    expect(body.collections.spaceaccess).toHaveLength(1)
  })

  it("result array is index-aligned to the input params", async () => {
    // 4 entries: alice readable, missing, alice readable, non-member
    const { app } = makeRouter("alice", [])
    const url = `/batch/pull?collections=spaceaccess&${params({
      spaceaccess: [
        { spaceId: "space-A" },
        { spaceId: "space-MISSING" },
        { spaceId: "space-B" },
        { spaceId: "space-C" },
      ],
    })}`
    const res = await app.request(url)
    const body = await res.json()
    const entries = body.collections.spaceaccess
    expect(entries).toHaveLength(4)
    expect(entries[0].data?.name).toBe("Alpha")
    expect(entries[1].error).toBe("Forbidden")
    expect(entries[2].data?.name).toBe("Beta")
    expect(entries[3].error).toBe("Forbidden")
  })
})
