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
  extra?: Record<string, unknown>,
) {
  // Write a minimal StoredDocument so the enricher can read it
  const data = { members, ...extra }
  const doc = {
    v: 1,
    data,
    timestamps: { members: Date.now() },
    hash: "test-hash",
  }
  await store.put(key, JSON.stringify(doc))
}

async function writeCandidacyDoc(
  store: MemoryObjectStore,
  key: string,
  status: string,
  message?: string,
) {
  const data: Record<string, string> = { status }
  if (message !== undefined) data.message = message
  await store.put(key, JSON.stringify({ v: 1, data, timestamps: {}, hash: "h" }))
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

// ── Candidacy unit tests ──────────────────────────────────────────────────────

describe("createGroupRoleEnricher — candidacy", () => {
  it("no candidacyPath → candidacy feature disabled, non-member gets no role", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", ["alice"], { candidacyEnabled: true })
    await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "pending")

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      // no candidacyPath — feature is disabled globally
    })

    const roles = await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
    expect(roles).toEqual([])
  })

  it("candidacyEnabled false in members doc → no candidacy role", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", ["alice"], { candidacyEnabled: false })
    await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "pending")

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
    })

    const roles = await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
    expect(roles).toEqual([])
  })

  it("candidacyEnabled absent in members doc → no candidacy role", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", ["alice"])
    await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "pending")

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
    })

    const roles = await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
    expect(roles).toEqual([])
  })

  it("pending candidacy + candidacyEnabled → grants candidacyRole", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", ["alice"], { candidacyEnabled: true })
    await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "pending", "Please let me in")

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
    })

    const roles = await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
    expect(roles).toEqual(["group-candidate"])
  })

  it("member with candidacy enabled → gets group-member, not group-candidate", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", ["alice"], { candidacyEnabled: true })
    await writeCandidacyDoc(store, "groups/group-1/candidacies/alice", "pending")

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
    })

    const roles = await enricher({ identity: "alice", roles: [] }, { groupId: "group-1" })
    expect(roles).toEqual(["group-member"])
  })

  it("accepted candidacy → no candidacy role (only 'pending' grants role)", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", ["alice"], { candidacyEnabled: true })
    await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "accepted")

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
    })

    // charlie is accepted but not yet in members list — no role until admin adds to members
    const roles = await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
    expect(roles).toEqual([])
  })

  it("denied candidacy → no candidacy role", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", ["alice"], { candidacyEnabled: true })
    await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "denied")

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
    })

    const roles = await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
    expect(roles).toEqual([])
  })

  it("no candidacy doc → no candidacy role", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", ["alice"], { candidacyEnabled: true })
    // no candidacy doc written

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
    })

    const roles = await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
    expect(roles).toEqual([])
  })

  it("respects custom candidacyRole", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", [], { candidacyEnabled: true })
    await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "pending")

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
      candidacyRole: "applicant",
    })

    const roles = await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
    expect(roles).toEqual(["applicant"])
  })

  it("respects custom candidacyStatusField", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", [], { candidacyEnabled: true })
    const doc = { v: 1, data: { state: "pending" }, timestamps: {}, hash: "h" }
    await store.put("groups/group-1/candidacies/charlie", JSON.stringify(doc))

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
      candidacyStatusField: "state",
    })

    const roles = await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
    expect(roles).toEqual(["group-candidate"])
  })

  it("respects custom candidacyEnabledField", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", [], { openToApplications: true })
    await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "pending")

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
      candidacyEnabledField: "openToApplications",
    })

    const roles = await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
    expect(roles).toEqual(["group-candidate"])
  })

  it("caches candidacy lookups", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", [], { candidacyEnabled: true })
    await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "pending")

    const getStringSpy = vi.spyOn(store, "getString")
    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
      cacheTtlMs: 60_000,
    })

    await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
    await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })

    // 1 read for members doc + 1 read for candidacy doc (second call served from cache)
    expect(getStringSpy).toHaveBeenCalledTimes(2)
  })

  it("candidacyCacheTtlMs: 0 disables candidacy caching", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", [], { candidacyEnabled: true })
    await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "pending")

    const getStringSpy = vi.spyOn(store, "getString")
    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
      cacheTtlMs: 60_000,
      candidacyCacheTtlMs: 0,
    })

    await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
    await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })

    // members cached (1 read), candidacy not cached (2 reads)
    expect(getStringSpy).toHaveBeenCalledTimes(3)
  })

  it("corrupt candidacy doc → no candidacy role", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", [], { candidacyEnabled: true })
    await store.put("groups/group-1/candidacies/charlie", "not valid json{{")

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
    })

    const roles = await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
    expect(roles).toEqual([])
  })
})

// ── Candidacy integration tests ───────────────────────────────────────────────

describe("createGroupRoleEnricher — candidacy integration via router", () => {
  function makeCandidacySetup(identity: string) {
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

    // Candidacy docs: user writes their own (self), admin reads/writes all
    const candidacyCol: CollectionConfig = {
      name: "candidacy",
      storagePath: "groups/{groupId}/candidacies/{identity}",
      readRoles: ["group-admin", "self"],
      writeRoles: ["group-admin", "self"],
      encryption: "none",
      maxBodyBytes: 4096,
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
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
      cacheTtlMs: 0, // no cache — changes take effect immediately
    })

    const config: SyncConfig = { version: 1, collections: [chatCol, candidacyCol, membersCol] }
    const opts: SyncRouterOptions = {
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({ identity, roles: [] }),
      roleEnricher: enricher,
    }
    return { app: createSyncRouter(opts), store }
  }

  it("pending candidate gets group-candidate role but cannot access member-only collection", async () => {
    const { app, store } = makeCandidacySetup("charlie")

    await writeMembersDoc(store, "groups/group-1/members", ["alice"], { candidacyEnabled: true })
    await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "pending", "Let me in!")

    const chatDoc = { v: 1, data: { messages: [] }, timestamps: {}, hash: "h" }
    await store.put("chats/group-1/2026-04-17", JSON.stringify(chatDoc))

    // charlie is a candidate, not a member — cannot access member-only collection
    const res = await app.request("/pull/chats/group-1/2026-04-17")
    expect(res.status).toBe(403)
  })

  it("candidate can push their own candidacy doc via self role", async () => {
    const { app, store } = makeCandidacySetup("charlie")

    await writeMembersDoc(store, "groups/group-1/members", ["alice"], { candidacyEnabled: true })

    // charlie pushes their application
    const res = await app.request("/push/groups/group-1/candidacies/charlie", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { status: "pending", message: "I'd like to join" }, baseHash: null }),
    })
    expect(res.status).toBe(200)
  })

  it("accepted candidate added to members gains group-member access", async () => {
    const { app, store } = makeCandidacySetup("charlie")

    await writeMembersDoc(store, "groups/group-1/members", ["alice"], { candidacyEnabled: true })
    await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "accepted")

    const chatDoc = { v: 1, data: { messages: [] }, timestamps: {}, hash: "h" }
    await store.put("chats/group-1/2026-04-17", JSON.stringify(chatDoc))

    // Admin accepts charlie but has not yet added them to members — no access
    let res = await app.request("/pull/chats/group-1/2026-04-17")
    expect(res.status).toBe(403)

    // Admin adds charlie to members doc
    await writeMembersDoc(store, "groups/group-1/members", ["alice", "charlie"], { candidacyEnabled: true })

    // Now charlie has group-member role
    res = await app.request("/pull/chats/group-1/2026-04-17")
    expect(res.status).toBe(200)
  })

  it("per-group toggle: candidacy disabled for group-2 even with candidacyPath set", async () => {
    const { app, store } = makeCandidacySetup("charlie")

    // group-1: candidacy enabled
    await writeMembersDoc(store, "groups/group-1/members", ["alice"], { candidacyEnabled: true })
    // group-2: candidacy disabled
    await writeMembersDoc(store, "groups/group-2/members", ["alice"], { candidacyEnabled: false })

    await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "pending")
    await writeCandidacyDoc(store, "groups/group-2/candidacies/charlie", "pending")

    const chatDoc = { v: 1, data: { messages: [] }, timestamps: {}, hash: "h" }
    await store.put("chats/group-1/2026-04-17", JSON.stringify(chatDoc))
    await store.put("chats/group-2/2026-04-17", JSON.stringify(chatDoc))

    // charlie is a pending candidate in group-1 (candidacy enabled) — still no member access
    let res = await app.request("/pull/chats/group-1/2026-04-17")
    expect(res.status).toBe(403)

    // charlie has pending doc in group-2 but candidacy is disabled — no role
    res = await app.request("/pull/chats/group-2/2026-04-17")
    expect(res.status).toBe(403)
  })
})

// ── Regression: correctness and security ─────────────────────────────────────

describe("createGroupRoleEnricher — regression: correctness and security", () => {
  // ── Issue #1: wrong identity substitution ──────────────────────────────────

  it("does not use URL {identity} param to resolve candidacy — auth.identity of non-applicant gets no role", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", [], { candidacyEnabled: true })
    // charlie (URL param identity) has a pending doc; admin (auth user) has none
    await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "pending")

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
      cacheTtlMs: 0,
    })

    // admin is the requesting user, but {identity: "charlie"} appears in URL params
    // (e.g. GET /pull/groups/group-1/candidacies/charlie triggers enricher with these params)
    const roles = await enricher(
      { identity: "admin", roles: [] },
      { groupId: "group-1", identity: "charlie" },
    )
    // admin has no candidacy doc → must get [] not charlie's role
    expect(roles).toEqual([])
  })

  it("uses auth.identity for candidacy when URL {identity} has a denied doc and auth user has pending", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", [], { candidacyEnabled: true })
    // charlie (URL identity) is denied; dave (auth user) is pending
    await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "denied")
    await writeCandidacyDoc(store, "groups/group-1/candidacies/dave", "pending")

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
      cacheTtlMs: 0,
    })

    // dave is auth'd but URL has {identity: "charlie"}
    // dave's own candidacy is pending → must get group-candidate
    const roles = await enricher(
      { identity: "dave", roles: [] },
      { groupId: "group-1", identity: "charlie" },
    )
    expect(roles).toEqual(["group-candidate"])
  })

  // ── Issue #2: TS logging on corrupt docs ──────────────────────────────────

  it("logs error when members document is corrupt", async () => {
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {})
    try {
      const store = new MemoryObjectStore(new Map())
      await store.put("groups/group-1/members", "not valid json{{")
      const enricher = createGroupRoleEnricher({
        store,
        membersPath: "groups/{groupId}/members",
        groupParam: "groupId",
      })
      await enricher({ identity: "alice", roles: [] }, { groupId: "group-1" })
      expect(consoleSpy).toHaveBeenCalled()
    } finally {
      consoleSpy.mockRestore()
    }
  })

  it("logs error when candidacy document is corrupt", async () => {
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {})
    try {
      const store = new MemoryObjectStore(new Map())
      await writeMembersDoc(store, "groups/group-1/members", [], { candidacyEnabled: true })
      await store.put("groups/group-1/candidacies/charlie", "not valid json{{")
      const enricher = createGroupRoleEnricher({
        store,
        membersPath: "groups/{groupId}/members",
        groupParam: "groupId",
        candidacyPath: "groups/{groupId}/candidacies/{identity}",
      })
      await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
      expect(consoleSpy).toHaveBeenCalled()
    } finally {
      consoleSpy.mockRestore()
    }
  })

  // ── Issue #3: corrupt docs must not poison cache ──────────────────────────

  it("does not cache corrupt members document — re-reads after document is fixed", async () => {
    const store = new MemoryObjectStore(new Map())
    await store.put("groups/group-1/members", "not valid json{{")

    const getStringSpy = vi.spyOn(store, "getString")
    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      cacheTtlMs: 60_000,
    })

    // First call: corrupt → empty membership
    const roles1 = await enricher({ identity: "alice", roles: [] }, { groupId: "group-1" })
    expect(roles1).toEqual([])
    expect(getStringSpy).toHaveBeenCalledTimes(1)

    // Document fixed in store
    await writeMembersDoc(store, "groups/group-1/members", ["alice"])

    // Second call within TTL — must NOT serve stale corrupt result from cache
    const roles2 = await enricher({ identity: "alice", roles: [] }, { groupId: "group-1" })
    expect(roles2).toEqual(["group-member"])
    expect(getStringSpy).toHaveBeenCalledTimes(2)
  })

  it("does not cache corrupt candidacy document — re-reads after document is fixed", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", [], { candidacyEnabled: true })
    await store.put("groups/group-1/candidacies/charlie", "not valid json{{")

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
      cacheTtlMs: 60_000,
    })

    // First call: corrupt → no candidacy role
    const roles1 = await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
    expect(roles1).toEqual([])

    // Document fixed in store
    await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "pending")

    // Second call within TTL — must NOT serve stale corrupt null from cache
    const roles2 = await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
    expect(roles2).toEqual(["group-candidate"])
  })

  it("does not cache a missing (null) candidacy document — re-reads after document is created", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeMembersDoc(store, "groups/group-1/members", [], { candidacyEnabled: true })
    // No candidacy doc written yet

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
      cacheTtlMs: 60_000,
    })

    // First call: doc absent → no candidacy role
    const roles1 = await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
    expect(roles1).toEqual([])

    // Charlie submits application
    await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "pending")

    // Second call within TTL — must NOT serve stale null from cache
    const roles2 = await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
    expect(roles2).toEqual(["group-candidate"])
  })

  // ── Issue #4: construction-time validation ────────────────────────────────

  it("throws when membersPath is missing the groupParam placeholder", () => {
    expect(() =>
      createGroupRoleEnricher({
        store: new MemoryObjectStore(new Map()),
        membersPath: "groups/members",
        groupParam: "groupId",
      }),
    ).toThrow(/groupId/)
  })

  it("throws when candidacyPath is empty string", () => {
    expect(() =>
      createGroupRoleEnricher({
        store: new MemoryObjectStore(new Map()),
        membersPath: "groups/{groupId}/members",
        groupParam: "groupId",
        candidacyPath: "",
      }),
    ).toThrow()
  })

  it("throws when candidacyPath is missing {identity} placeholder", () => {
    expect(() =>
      createGroupRoleEnricher({
        store: new MemoryObjectStore(new Map()),
        membersPath: "groups/{groupId}/members",
        groupParam: "groupId",
        candidacyPath: "groups/{groupId}/candidacies/fixed",
      }),
    ).toThrow(/identity/)
  })

  it("throws when candidacyPath is missing the groupParam placeholder", () => {
    expect(() =>
      createGroupRoleEnricher({
        store: new MemoryObjectStore(new Map()),
        membersPath: "groups/{groupId}/members",
        groupParam: "groupId",
        candidacyPath: "candidacies/{identity}",
      }),
    ).toThrow(/groupId/)
  })

  // ── Issue #5: candidacy cache TTL expiry ──────────────────────────────────

  it("candidacy cache expires after its TTL while members cache stays warm", async () => {
    vi.useFakeTimers()
    try {
      const store = new MemoryObjectStore(new Map())
      await writeMembersDoc(store, "groups/group-1/members", [], { candidacyEnabled: true })
      await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "pending")

      const getStringSpy = vi.spyOn(store, "getString")
      const enricher = createGroupRoleEnricher({
        store,
        membersPath: "groups/{groupId}/members",
        groupParam: "groupId",
        candidacyPath: "groups/{groupId}/candidacies/{identity}",
        cacheTtlMs: 60_000,       // long members TTL
        candidacyCacheTtlMs: 5_000, // short candidacy TTL
      })

      // Call 1: reads members + candidacy → both cached
      await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
      expect(getStringSpy).toHaveBeenCalledTimes(2)

      // Call 2: within candidacy TTL → both from cache
      vi.advanceTimersByTime(4_999)
      await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
      expect(getStringSpy).toHaveBeenCalledTimes(2)

      // Call 3: after candidacy TTL → re-reads candidacy only (members still warm)
      vi.advanceTimersByTime(2)
      await enricher({ identity: "charlie", roles: [] }, { groupId: "group-1" })
      expect(getStringSpy).toHaveBeenCalledTimes(3)
    } finally {
      vi.useRealTimers()
    }
  })

  // ── Issue #6: group-candidate as access-granting role ────────────────────

  it("pending candidate gets 200 on a collection gated by the candidacy role", async () => {
    const store = new MemoryObjectStore(new Map())

    const infoCol: CollectionConfig = {
      name: "group-info",
      storagePath: "groups/{groupId}/info",
      readRoles: ["group-candidate", "group-member"],
      writeRoles: ["group-admin"],
      encryption: "none",
      maxBodyBytes: 4_096,
      allowedMimeTypes: ["application/json"],
    }
    const candidacyCol: CollectionConfig = {
      name: "candidacy",
      storagePath: "groups/{groupId}/candidacies/{identity}",
      readRoles: ["group-admin", "self"],
      writeRoles: ["group-admin", "self"],
      encryption: "none",
      maxBodyBytes: 4_096,
      allowedMimeTypes: ["application/json"],
    }
    const membersCol: CollectionConfig = {
      name: "group-members",
      storagePath: "groups/{groupId}/members",
      readRoles: ["group-admin"],
      writeRoles: ["group-admin"],
      encryption: "none",
      maxBodyBytes: 65_536,
      allowedMimeTypes: ["application/json"],
    }

    await writeMembersDoc(store, "groups/group-1/members", ["alice"], { candidacyEnabled: true })
    await writeCandidacyDoc(store, "groups/group-1/candidacies/charlie", "pending")
    await store.put(
      "groups/group-1/info",
      JSON.stringify({ v: 1, data: { welcome: "hello" }, timestamps: {}, hash: "h" }),
    )

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
      cacheTtlMs: 0,
    })
    const config: SyncConfig = { version: 1, collections: [infoCol, candidacyCol, membersCol] }

    // charlie: pending candidate → gets group-candidate → can read group info
    const charlieApp = createSyncRouter({
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({ identity: "charlie", roles: [] }),
      roleEnricher: enricher,
    })
    const resCharlie = await charlieApp.request("/pull/groups/group-1/info")
    expect(resCharlie.status).toBe(200)

    // dave: no candidacy doc → no role → 403
    const daveApp = createSyncRouter({
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({ identity: "dave", roles: [] }),
      roleEnricher: enricher,
    })
    const resDave = await daveApp.request("/pull/groups/group-1/info")
    expect(resDave.status).toBe(403)
  })

  // ── Issue #8: cache key collision ────────────────────────────────────────

  it("does not produce a candidacy cache collision when groupId or identity contains a colon", async () => {
    const store = new MemoryObjectStore(new Map())
    // groupId="a:b", identity="c" → has a pending candidacy doc
    await writeMembersDoc(store, "groups/a:b/members", [], { candidacyEnabled: true })
    await writeCandidacyDoc(store, "groups/a:b/candidacies/c", "pending")
    // groupId="a", identity="b:c" → NO candidacy doc
    await writeMembersDoc(store, "groups/a/members", [], { candidacyEnabled: true })

    const enricher = createGroupRoleEnricher({
      store,
      membersPath: "groups/{groupId}/members",
      groupParam: "groupId",
      candidacyPath: "groups/{groupId}/candidacies/{identity}",
      cacheTtlMs: 60_000,
    })

    // "a:b" + "c" → pending → group-candidate (caches under key for this pair)
    const roles1 = await enricher({ identity: "c", roles: [] }, { groupId: "a:b" })
    expect(roles1).toEqual(["group-candidate"])

    // "a" + "b:c" → no doc → must NOT collide with the cached entry above
    const roles2 = await enricher({ identity: "b:c", roles: [] }, { groupId: "a" })
    expect(roles2).toEqual([])
  })
})
