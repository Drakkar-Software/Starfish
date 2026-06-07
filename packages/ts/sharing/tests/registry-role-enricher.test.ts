import { describe, it, expect } from "vitest"
import {
  MemoryObjectStore,
  type ObjectStore,
  type AuthResult,
} from "@drakkar.software/starfish-server"
import { makeRegistryRoleEnricher } from "../src/registry-role-enricher.js"

const REGISTRY_PATH = "products/{id}/_registry"
const OWNER = "product:owner"
const MEMBER = "product:member"

function makeEnricher(store: ObjectStore, allowTofu = true) {
  return makeRegistryRoleEnricher(store, {
    idParam: "productId",
    registryPath: REGISTRY_PATH,
    ownerRole: OWNER,
    memberRole: MEMBER,
    allowTofu,
  })
}

async function writeRegistry(store: MemoryObjectStore, id: string, doc: unknown) {
  await store.put(`products/${id}/_registry`, JSON.stringify(doc))
}

function auth(identity: string): AuthResult {
  return { identity, roles: [] }
}

// A store whose getString always rejects, for the fail-closed test.
const raisingStore: ObjectStore = {
  async getString(): Promise<string | null> {
    throw new Error("store boom")
  },
  async put() {},
  async listKeys() {
    return []
  },
  async getBytes() {
    return null
  },
  async putBytes() {},
  async delete() {},
  async deleteMany() {},
}

describe("makeRegistryRoleEnricher", () => {
  it("missing doc + allowTofu grants owner and member", async () => {
    const store = new MemoryObjectStore(new Map())
    expect(await makeEnricher(store)(auth("alice"), { productId: "p1" })).toEqual([OWNER, MEMBER])
  })

  it("missing doc + strict grants nothing", async () => {
    const store = new MemoryObjectStore(new Map())
    expect(await makeEnricher(store, false)(auth("alice"), { productId: "p1" })).toEqual([])
  })

  it("store error propagates (fail closed)", async () => {
    await expect(makeEnricher(raisingStore)(auth("alice"), { productId: "p1" })).rejects.toThrow(
      "store boom",
    )
  })

  it("owner-less doc denies", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeRegistry(store, "p1", { data: { members: ["alice"] } })
    expect(await makeEnricher(store)(auth("alice"), { productId: "p1" })).toEqual([])
  })

  it("owner match grants owner and member", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeRegistry(store, "p1", { data: { owner: "alice", members: [] } })
    expect(await makeEnricher(store)(auth("alice"), { productId: "p1" })).toEqual([OWNER, MEMBER])
  })

  it("member match grants member only", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeRegistry(store, "p1", { data: { owner: "alice", members: ["bob"] } })
    expect(await makeEnricher(store)(auth("bob"), { productId: "p1" })).toEqual([MEMBER])
  })

  it("stranger gets nothing", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeRegistry(store, "p1", { data: { owner: "alice", members: ["bob"] } })
    expect(await makeEnricher(store)(auth("carol"), { productId: "p1" })).toEqual([])
  })

  it("bad id fails full match", async () => {
    const store = new MemoryObjectStore(new Map())
    expect(await makeEnricher(store)(auth("alice"), { productId: "bad id!" })).toEqual([])
  })

  it("trailing-newline id denied", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeRegistry(store, "p1", { data: { owner: "alice", members: [] } })
    expect(await makeEnricher(store)(auth("alice"), { productId: "p1\n" })).toEqual([])
  })

  it("missing id param", async () => {
    const store = new MemoryObjectStore(new Map())
    expect(await makeEnricher(store)(auth("alice"), {})).toEqual([])
  })

  it("empty identity", async () => {
    const store = new MemoryObjectStore(new Map())
    expect(await makeEnricher(store)(auth(""), { productId: "p1" })).toEqual([])
  })

  it("bare object doc parsed", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeRegistry(store, "p1", { owner: "alice", members: ["bob"] })
    expect(await makeEnricher(store)(auth("alice"), { productId: "p1" })).toEqual([OWNER, MEMBER])
    expect(await makeEnricher(store)(auth("bob"), { productId: "p1" })).toEqual([MEMBER])
  })

  it("data-wrapped doc parsed", async () => {
    const store = new MemoryObjectStore(new Map())
    await writeRegistry(store, "p1", { data: { owner: "alice", members: ["bob"] } })
    expect(await makeEnricher(store)(auth("bob"), { productId: "p1" })).toEqual([MEMBER])
  })

  it("unparseable doc denies", async () => {
    const store = new MemoryObjectStore(new Map())
    await store.put("products/p1/_registry", "not json{{")
    expect(await makeEnricher(store)(auth("alice"), { productId: "p1" })).toEqual([])
  })
})
