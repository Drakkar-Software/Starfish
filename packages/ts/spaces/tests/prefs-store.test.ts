/**
 * Tests for createPrefsStore — the generic per-identity preference store.
 *
 * Covers both cadences with a small `{ nodes: Record<string, number> }` shape:
 *  - write-through (mutes-like): immediate server sync applying the per-op change
 *  - debounced (reads-like): batched flush of the cache snapshot via `merge`
 * plus KV persistence, hydrate (server-wins vs max-merge), and the in-flight guard.
 */
import { describe, it, expect, vi, beforeEach } from "vitest"
import type { StarfishClient } from "@drakkar.software/starfish-client"
import type { Session } from "../src/session.js"
import { configureSpaces } from "../src/config.js"
import { createPrefsStore } from "../src/prefs-store.js"
import { clearDocCache } from "../src/doc-cache.js"

interface Marks {
  nodes: Record<string, number>
}
const EMPTY: Marks = { nodes: {} }

const coerce = (raw: unknown): Marks => {
  const r = raw as { nodes?: unknown } | undefined
  const nodes = r?.nodes && typeof r.nodes === "object" ? (r.nodes as Record<string, number>) : {}
  return { nodes }
}

/** Max-merge (reads semantics): keep the larger timestamp per node. */
const maxMerge = (base: Marks, over: Marks): Marks | null => {
  let nodes: Record<string, number> | null = null
  for (const [id, ts] of Object.entries(over.nodes)) {
    if (!(id in base.nodes) || ts > base.nodes[id]) {
      nodes ??= { ...base.nodes }
      nodes[id] = ts
    }
  }
  return nodes ? { nodes } : null
}

/** In-memory KV adapter. */
function makeKv() {
  const map = new Map<string, string>()
  return {
    map,
    adapter: {
      getItem: async (k: string) => map.get(k) ?? null,
      setItem: async (k: string, v: string) => void map.set(k, v),
      removeItem: async (k: string) => void map.delete(k),
    },
  }
}

/** A session whose registry client records push payloads and serves a mutable doc. */
function makeSession(initialExtra: Record<string, unknown> = {}) {
  let doc: Record<string, unknown> = { spaces: [], caps: {}, pubAccess: {}, ...initialExtra }
  let hash = "H0"
  const pushSpy = vi.fn(async (_path: string, body: Record<string, unknown>) => {
    const { v: _v, hash: _h, ...rest } = body
    doc = rest
    hash = `H${Math.random().toString(36).slice(2, 6)}`
    return { hash, timestamp: 1 }
  })
  const client = {
    pull: vi.fn(async () => ({ data: doc, hash })),
    push: pushSpy,
    peekCache: vi.fn(async () => null),
  } as unknown as StarfishClient
  const session = {
    userId: "u1",
    spacesRegistryClient: client,
    accountClient: client,
    layout: {
      spacesPull: (u: string) => `/pull/user/${u}/_spaces`,
      spacesPush: (u: string) => `/push/user/${u}/_spaces`,
    },
  } as unknown as Session
  return { session, client, pushSpy, getDoc: () => doc }
}

beforeEach(() => {
  clearDocCache()
  configureSpaces({ kvAdapter: undefined })
})

describe("createPrefsStore", () => {
  it("write-through: mutate emits locally, persists to KV, and syncs to server", async () => {
    const { adapter, map } = makeKv()
    configureSpaces({ kvAdapter: adapter })
    const { session, pushSpy, getDoc } = makeSession()
    const store = createPrefsStore<Marks>({
      field: "marks",
      client: (s) => s.spacesRegistryClient,
      empty: EMPTY,
      coerce,
      merge: (base, incoming) => (JSON.stringify(base) === JSON.stringify(incoming) ? null : incoming),
      kvKey: (u) => `app.marks.${u}`,
    })

    await store.mutate(session, (cur) => ({ nodes: { ...cur.nodes, a: 5 } }))

    expect(store.get()).toEqual({ nodes: { a: 5 } })
    expect(JSON.parse(map.get("app.marks.u1")!)).toEqual({ nodes: { a: 5 } })
    expect(pushSpy).toHaveBeenCalledTimes(1)
    expect((getDoc() as { marks: Marks }).marks).toEqual({ nodes: { a: 5 } })
  })

  it("write-through: mutate returning null does not emit or push", async () => {
    const { session, pushSpy } = makeSession()
    const store = createPrefsStore<Marks>({
      field: "marks",
      client: (s) => s.spacesRegistryClient,
      empty: EMPTY,
      coerce,
      merge: maxMerge,
      kvKey: (u) => `app.marks.${u}`,
    })
    await store.mutate(session, () => null)
    expect(store.get()).toEqual(EMPTY)
    expect(pushSpy).not.toHaveBeenCalled()
  })

  it("debounced: mutate defers the server push until the flush window", async () => {
    vi.useFakeTimers()
    try {
      const { session, pushSpy } = makeSession()
      const store = createPrefsStore<Marks>({
        field: "reads",
        client: (s) => s.spacesRegistryClient,
        empty: EMPTY,
        coerce,
        merge: maxMerge,
        kvKey: (u) => `app.reads.${u}`,
        flushDelayMs: 8000,
      })
      await store.mutate(session, (cur) => (5 > (cur.nodes.a ?? 0) ? { nodes: { ...cur.nodes, a: 5 } } : null))
      await store.mutate(session, (cur) => (7 > (cur.nodes.b ?? 0) ? { nodes: { ...cur.nodes, b: 7 } } : null))
      expect(store.get()).toEqual({ nodes: { a: 5, b: 7 } })
      expect(pushSpy).not.toHaveBeenCalled() // still batched
      await store.flushNow()
      expect(pushSpy).toHaveBeenCalledTimes(1)
    } finally {
      vi.useRealTimers()
    }
  })

  it("hydrate with max-merge keeps the larger per-node timestamp", async () => {
    const { session } = makeSession()
    const store = createPrefsStore<Marks>({
      field: "reads",
      client: (s) => s.spacesRegistryClient,
      empty: EMPTY,
      coerce,
      merge: maxMerge,
      kvKey: (u) => `app.reads.${u}`,
      flushDelayMs: 8000,
    })
    await store.mutate(session, () => ({ nodes: { a: 10, b: 2 } }))
    await store.hydrate("u1", { nodes: { a: 5, b: 9, c: 1 } })
    expect(store.get()).toEqual({ nodes: { a: 10, b: 9, c: 1 } })
  })

  it("hydrate folds KV + legacy when foldKvOnHydrate is set", async () => {
    const { adapter, map } = makeKv()
    map.set("app.reads.u1", JSON.stringify({ nodes: { a: 3 } }))
    map.set("app.lastread.u1", JSON.stringify({ nodes: { z: 100 } }))
    configureSpaces({ kvAdapter: adapter })
    const { session } = makeSession()
    const store = createPrefsStore<Marks>({
      field: "reads",
      client: (s) => s.spacesRegistryClient,
      empty: EMPTY,
      coerce,
      merge: maxMerge,
      kvKey: (u) => `app.reads.${u}`,
      legacyKeys: (u) => [`app.lastread.${u}`],
      flushDelayMs: 8000,
      foldKvOnHydrate: true,
    })
    void session
    await store.hydrate("u1", { nodes: { a: 1, b: 8 } })
    expect(store.get()).toEqual({ nodes: { a: 3, z: 100, b: 8 } })
  })
})
