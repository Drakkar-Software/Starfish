import { describe, it, expect, vi, beforeEach } from "vitest"
import { webcrypto } from "node:crypto"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
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

async function writeMembersDoc(
  store: MemoryObjectStore,
  key: string,
  members: string[],
) {
  // Write a minimal StoredDocument so the enricher can read it
  const data = { members }
  const doc = {
    v: 1,
    data,
    timestamps: { members: Date.now() },
    hash: "test-hash",
  }
  await store.put(key, JSON.stringify(doc))
}

// ── Unit tests for the enricher function ─────────────────────────────────────

describe("createGroupRoleEnricher — unit", () => {
  it("grants the role when user is a member", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", ["alice", "bob"])

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
    })

    const roles = await enricher({ identity: "alice", roles: [] }, { groupId: "group-1" })
    expect(roles).toEqual(["group-member"])
  })

  it("returns no roles when user is not a member", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", ["alice", "bob"])

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
    })

    const roles = await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
    expect(roles).toEqual([])
  })

  it("returns no roles when groupParam is absent from params", async () => {
    const store = new MemoryObjectStore(new Map())
    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
    })
    const roles = await enricher({ identity: "alice", roles: [] }, {})
    expect(roles).toEqual([])
  })

  it("returns no roles when members document does not exist", async () => {
    const store = new MemoryObjectStore(new Map())
    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
    })
    const roles = await enricher({ identity: "alice", roles: [] }, { groupId: "nonexistent" })
    expect(roles).toEqual([])
  })

  it("respects custom membersField", async () => {
    const store = new MemoryObjectStore(new Map())
    const doc = { v: 1, data: { participants: ["alice"] }, timestamps: { participants: Date.now() }, hash: "h" }
    await store.put("groups/group-1/members", JSON.stringify(doc))

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      membersField: "participants",
    })
    const roles = await enricher({ identity: "alice", roles: [] }, { groupId: "group-1" })
    expect(roles).toEqual(["group-member"])
  })

  it("respects custom role", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", ["alice"])

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      role: "chat-member",
    })
    const roles = await enricher({ identity: "alice", roles: [] }, { groupId: "group-1" })
    expect(roles).toEqual(["chat-member"])
  })

  it("caches membership lookups", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", ["alice"])

    const getStringSpy = vi.spyOn(store, "getString")
    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      cacheTtlMs: 60_000,
    })

    await enricher({ identity: "alice", roles: [] }, { groupId: "group-1" })
    await enricher({ identity: "alice", roles: [] }, { groupId: "group-1" })
    await enricher({ identity: "bob", roles: [] }, { groupId: "group-1" })

    // getString called only once — second and third calls served from cache
    expect(getStringSpy).toHaveBeenCalledTimes(1)
  })

  it("bypasses cache when cacheTtlMs is 0", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", ["alice"])

    const getStringSpy = vi.spyOn(store, "getString")
    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      cacheTtlMs: 0,
    })

    await enricher({ identity: "alice", roles: [] }, { groupId: "group-1" })
    await enricher({ identity: "alice", roles: [] }, { groupId: "group-1" })

    expect(getStringSpy).toHaveBeenCalledTimes(2)
  })

  it("handles corrupted document gracefully (empty membership)", async () => {
    const store = new MemoryObjectStore(new Map())
    await store.put("groups/group-1/members", "not valid json{{")

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
    })
    const roles = await enricher({ identity: "alice", roles: [] }, { groupId: "group-1" })
    expect(roles).toEqual([])
  })

  it("handles non-array members field gracefully", async () => {
    const store = new MemoryObjectStore(new Map())
    const doc = { v: 1, data: { members: "alice" }, timestamps: {}, hash: "h" }
    await store.put("groups/group-1/members", JSON.stringify(doc))

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
    })
    const roles = await enricher({ identity: "alice", roles: [] }, { groupId: "group-1" })
    expect(roles).toEqual([])
  })
})

// ── Integration tests through the router ─────────────────────────────────────

describe("createGroupRoleEnricher — integration via router", () => {
  function makeIntegrationSetup(identity: string, roles: string[] = []) {
    const store = new MemoryObjectStore(new Map())

    const chatCol: CollectionConfig = {
      name: "chat",
      storagePath: "chats/{groupId}/{day}",
      readRoles: ["group-member"],
      writeRoles: ["group-member"],
      encryption: "none",
      maxBodyBytes: 65536,
      allowedMimeTypes: ["application/json"],
      listable: true,
    }

    const membersCol: CollectionConfig = {
      name: "group-members",
      storagePath: "groups/{groupId}/members",
      readRoles: ["group-admin"],
      writeRoles: ["group-admin"],
      encryption: "none",
      maxBodyBytes: 65536,
      allowedMimeTypes: ["application/json"],
    }

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
    })

    const config: SyncConfig = { version: 1, collections: [chatCol, membersCol] }
    const opts: SyncRouterOptions = {
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({ identity, roles }),
      roleEnricher: enricher,
    }
    return { app: createSyncRouter(opts), store }
  }

  it("grants pull access to group members", async () => {
    const { app, store } = makeIntegrationSetup("alice")

    // Write alice as a member directly to the store
    const membersDoc = {
      v: 1,
      data: { members: ["alice", "bob"] },
      timestamps: { members: Date.now() },
      hash: "h",
    }
    await store.put("groups/group-1/members", JSON.stringify(membersDoc))

    // Write a chat message as bob (also a member)
    const chatDoc = {
      v: 1,
      data: { messages: [{ text: "hi" }] },
      timestamps: { messages: Date.now() },
      hash: "h",
    }
    await store.put("chats/group-1/2026-04-13", JSON.stringify(chatDoc))

    const res = await app.request("/pull/chats/group-1/2026-04-13")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data.messages).toBeDefined()
  })

  it("denies access to non-members (403)", async () => {
    const { app, store } = makeIntegrationSetup("charlie")

    const membersDoc = {
      v: 1,
      data: { members: ["alice", "bob"] },
      timestamps: { members: Date.now() },
      hash: "h",
    }
    await store.put("groups/group-1/members", JSON.stringify(membersDoc))

    const res = await app.request("/pull/chats/group-1/2026-04-13")
    expect(res.status).toBe(403)
  })

  it("members can push chat messages", async () => {
    const { app, store } = makeIntegrationSetup("alice")

    const membersDoc = {
      v: 1,
      data: { members: ["alice"] },
      timestamps: { members: Date.now() },
      hash: "h",
    }
    await store.put("groups/group-1/members", JSON.stringify(membersDoc))

    const res = await app.request("/push/chats/group-1/2026-04-13", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { messages: [] }, baseHash: null }),
    })
    expect(res.status).toBe(200)
  })

  it("members can list available days", async () => {
    const { app, store } = makeIntegrationSetup("alice")

    const membersDoc = {
      v: 1,
      data: { members: ["alice"] },
      timestamps: { members: Date.now() },
      hash: "h",
    }
    await store.put("groups/group-1/members", JSON.stringify(membersDoc))

    // Write a couple of chat days
    for (const day of ["2026-04-12", "2026-04-13"]) {
      const chatDoc = { v: 1, data: { messages: [] }, timestamps: { messages: Date.now() }, hash: "h" }
      await store.put(`chats/group-1/${day}`, JSON.stringify(chatDoc))
    }

    const res = await app.request("/list/chats/group-1")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.items.sort()).toEqual(["2026-04-12", "2026-04-13"])
  })

  it("non-members cannot list days (403)", async () => {
    const { app, store } = makeIntegrationSetup("charlie")

    const membersDoc = {
      v: 1,
      data: { members: ["alice"] },
      timestamps: { members: Date.now() },
      hash: "h",
    }
    await store.put("groups/group-1/members", JSON.stringify(membersDoc))

    const res = await app.request("/list/chats/group-1")
    expect(res.status).toBe(403)
  })
})

// ── Additional coverage ───────────────────────────────────────────────────────

describe("createGroupRoleEnricher — additional coverage", () => {
  it("non-members cannot push (403)", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", ["alice", "bob"])

    const chatCol: CollectionConfig = {
      name: "chat",
      storagePath: "chats/{groupId}/{day}",
      readRoles: ["group-member"],
      writeRoles: ["group-member"],
      encryption: "none",
      maxBodyBytes: 65536,
      allowedMimeTypes: ["application/json"],
      listable: true,
    }
    const membersCol: CollectionConfig = {
      name: "group-members",
      storagePath: "groups/{groupId}/members",
      readRoles: ["group-admin"],
      writeRoles: ["group-admin"],
      encryption: "none",
      maxBodyBytes: 65536,
      allowedMimeTypes: ["application/json"],
    }
    const config: SyncConfig = { version: 1, collections: [chatCol, membersCol] }
    const app = createSyncRouter({
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({ identity: "charlie", roles: [] }),
      roleEnricher: createGroupRoleEnricher({
        store,
        membersPath: "groups/{groupId}/members",
        groupParam: "groupId",
      }),
    })

    const res = await app.request("/push/chats/group-1/2026-04-14", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { messages: [] }, baseHash: null }),
    })
    expect(res.status).toBe(403)
  })

  it("user gains access after being added to the members document", async () => {
    const store = new MemoryObjectStore(new Map())

    // Start: charlie is NOT a member
    await writeMembersDoc(store, "groups/group-1/members", ["alice"])

    // Write a chat doc for charlie to eventually read
    const chatDoc = { v: 1, data: { messages: [] }, timestamps: { messages: Date.now() }, hash: "h" }
    await store.put("chats/group-1/2026-04-14", JSON.stringify(chatDoc))

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      cacheTtlMs: 0, // no cache — membership changes take effect immediately
    })

    const chatCol: CollectionConfig = {
      name: "chat",
      storagePath: "chats/{groupId}/{day}",
      readRoles: ["group-member"],
      writeRoles: ["group-member"],
      encryption: "none",
      maxBodyBytes: 65536,
      allowedMimeTypes: ["application/json"],
      listable: true,
    }
    const membersCol: CollectionConfig = {
      name: "group-members",
      storagePath: "groups/{groupId}/members",
      readRoles: ["group-admin"],
      writeRoles: ["group-admin"],
      encryption: "none",
      maxBodyBytes: 65536,
      allowedMimeTypes: ["application/json"],
    }
    const config: SyncConfig = { version: 1, collections: [chatCol, membersCol] }
    const app = createSyncRouter({
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({ identity: "charlie", roles: [] }),
      roleEnricher: enricher,
    })

    // Charlie is not yet a member — pull denied
    let res = await app.request("/pull/chats/group-1/2026-04-14")
    expect(res.status).toBe(403)

    // Admin adds charlie to the members doc
    await writeMembersDoc(store, "groups/group-1/members", ["alice", "charlie"])

    // Charlie now has access (cache disabled, enricher re-reads immediately)
    res = await app.request("/pull/chats/group-1/2026-04-14")
    expect(res.status).toBe(200)
  })

  it("user loses access after being removed from the members document", async () => {
    const store = new MemoryObjectStore(new Map())

    // Start: alice IS a member
    await writeMembersDoc(store, "groups/group-1/members", ["alice", "bob"])

    const chatDoc = { v: 1, data: { messages: [] }, timestamps: { messages: Date.now() }, hash: "h" }
    await store.put("chats/group-1/2026-04-14", JSON.stringify(chatDoc))

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      cacheTtlMs: 0, // no cache — membership changes take effect immediately
    })

    const chatCol: CollectionConfig = {
      name: "chat",
      storagePath: "chats/{groupId}/{day}",
      readRoles: ["group-member"],
      writeRoles: ["group-member"],
      encryption: "none",
      maxBodyBytes: 65536,
      allowedMimeTypes: ["application/json"],
      listable: true,
    }
    const membersCol: CollectionConfig = {
      name: "group-members",
      storagePath: "groups/{groupId}/members",
      readRoles: ["group-admin"],
      writeRoles: ["group-admin"],
      encryption: "none",
      maxBodyBytes: 65536,
      allowedMimeTypes: ["application/json"],
    }
    const config: SyncConfig = { version: 1, collections: [chatCol, membersCol] }
    const app = createSyncRouter({
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({ identity: "alice", roles: [] }),
      roleEnricher: enricher,
    })

    // Alice is a member — pull succeeds
    let res = await app.request("/pull/chats/group-1/2026-04-14")
    expect(res.status).toBe(200)

    // Admin removes alice from the members doc
    await writeMembersDoc(store, "groups/group-1/members", ["bob"])

    // Alice can no longer pull (cache is disabled)
    res = await app.request("/pull/chats/group-1/2026-04-14")
    expect(res.status).toBe(403)
  })

  it("cache expires after TTL and re-reads from store", async () => {
    vi.useFakeTimers()
    try {
      const store = new MemoryObjectStore(new Map())
      await writeMembersDoc(store, "groups/group-1/members", ["alice"])

      const getStringSpy = vi.spyOn(store, "getString")
      const enricher = createGroupRoleEnricher({
        store,
        membersPath: "groups/{groupId}/members",
        groupParam: "groupId",
        cacheTtlMs: 5_000,
      })

      // First call — reads from store, populates cache
      await enricher({ identity: "alice", roles: [] }, { groupId: "group-1" })
      expect(getStringSpy).toHaveBeenCalledTimes(1)

      // Second call within TTL — served from cache
      vi.advanceTimersByTime(4_999)
      await enricher({ identity: "alice", roles: [] }, { groupId: "group-1" })
      expect(getStringSpy).toHaveBeenCalledTimes(1)

      // Third call after TTL has elapsed — cache expired, re-reads from store
      vi.advanceTimersByTime(2)
      await enricher({ identity: "alice", roles: [] }, { groupId: "group-1" })
      expect(getStringSpy).toHaveBeenCalledTimes(2)
    } finally {
      vi.useRealTimers()
    }
  })
})
