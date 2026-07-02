import { describe, it, expect } from "vitest"
import { webcrypto } from "node:crypto"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { createSyncRouter, type SyncRouterOptions, type AuthResult } from "../../src/router/route-builder.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import type { SyncConfig, CollectionConfig } from "../../src/config/schema.js"
import { validateConfig, collectConfigWarnings } from "../../src/config/validate.js"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

function makeCol(overrides: Partial<CollectionConfig> = {}): CollectionConfig {
  return {
    name: "chat",
    storagePath: "chats/{groupId}/{day}",
    readRoles: ["member"],
    writeRoles: ["member"],
    encryption: "none",
    maxBodyBytes: 65536,
    allowedMimeTypes: ["application/json"],
    listable: true,
    ...overrides,
  }
}

function makeRouter(col: CollectionConfig, global?: SyncConfig["rateLimit"], identity = "user-1", trustedProxyHops = 0) {
  const store = new MemoryObjectStore(new Map())
  const config: SyncConfig = { version: 1, collections: [col], rateLimit: global }
  const opts: SyncRouterOptions = {
    store,
    config,
    roleResolver: async (): Promise<AuthResult> => ({ identity, roles: ["member"] }),
    trustedProxyHops,
  }
  return { app: createSyncRouter(opts), store }
}

const PULL = "/pull/chats/group-1/day-1"
const LIST = "/list/chats/group-1"

// Push to a distinct document each call (the rate limiter is per-collection, not
// per-document) so repeated pushes don't trip hash-conflict (409) detection.
let pushSeq = 0
function push(app: ReturnType<typeof createSyncRouter>, headers: Record<string, string> = {}) {
  pushSeq += 1
  return app.request(`/push/chats/group-1/day-${pushSeq}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify({ data: { msg: "hi" }, baseHash: null }),
  })
}

describe("per-action collection rate limiting", () => {
  it("limits push independently — pull/list are unaffected by a push rule", async () => {
    const { app } = makeRouter(makeCol({ rateLimit: { push: { windowMs: 60_000, maxRequests: 2 } } }))

    expect((await push(app)).status).toBe(200)
    expect((await push(app)).status).toBe(200)
    expect((await push(app)).status).toBe(429) // 3rd push over the limit of 2

    // pull and list have no rule → never throttled, even after push is exhausted
    for (let i = 0; i < 5; i++) {
      expect((await app.request(PULL)).status).toBe(200)
      expect((await app.request(LIST)).status).toBe(200)
    }
  })

  it("limits pull independently — push is unaffected by a pull rule", async () => {
    const { app } = makeRouter(makeCol({ rateLimit: { pull: { windowMs: 60_000, maxRequests: 1 } } }))

    expect((await app.request(PULL)).status).toBe(200)
    expect((await app.request(PULL)).status).toBe(429) // 2nd pull over the limit of 1

    // push has no rule → unaffected
    expect((await push(app)).status).toBe(200)
    expect((await push(app)).status).toBe(200)
  })

  it("limits list independently", async () => {
    const { app } = makeRouter(makeCol({ rateLimit: { list: { windowMs: 60_000, maxRequests: 1 } } }))
    expect((await app.request(LIST)).status).toBe(200)
    expect((await app.request(LIST)).status).toBe(429)
  })

  it("each action keeps its own counter (push limit does not consume pull budget)", async () => {
    const { app } = makeRouter(
      makeCol({ rateLimit: { push: { windowMs: 60_000, maxRequests: 1 }, pull: { windowMs: 60_000, maxRequests: 1 } } }),
    )
    expect((await push(app)).status).toBe(200)
    expect((await push(app)).status).toBe(429) // push exhausted
    expect((await app.request(PULL)).status).toBe(200) // pull still has its own budget
    expect((await app.request(PULL)).status).toBe(429)
  })

  it('bucket "ip" separates callers by X-Forwarded-For even when identity is constant', async () => {
    // roleResolver returns a fixed identity, so identity-bucketing would group all
    // requests; "ip" mode must instead split by X-Forwarded-For. trustedProxyHops=1
    // opts into trusting the single-hop XFF as the client IP.
    const { app } = makeRouter(makeCol({ rateLimit: { push: { windowMs: 60_000, maxRequests: 1, bucket: "ip" } } }), undefined, "user-1", 1)
    expect((await push(app, { "X-Forwarded-For": "1.1.1.1" })).status).toBe(200)
    expect((await push(app, { "X-Forwarded-For": "1.1.1.1" })).status).toBe(429) // same IP exhausted
    expect((await push(app, { "X-Forwarded-For": "2.2.2.2" })).status).toBe(200) // different IP, fresh budget
  })

  it('with default trustedProxyHops=0, a spoofed X-Forwarded-For cannot bypass "ip" bucketing', async () => {
    // No trusted proxy configured → the client-controlled XFF is ignored; Hono has no
    // socket IP, so every request collapses to the one "anonymous" bucket even though
    // the attacker rotates X-Forwarded-For on each request.
    const { app } = makeRouter(makeCol({ rateLimit: { push: { windowMs: 60_000, maxRequests: 1, bucket: "ip" } } }))
    expect((await push(app, { "X-Forwarded-For": "1.1.1.1" })).status).toBe(200)
    expect((await push(app, { "X-Forwarded-For": "2.2.2.2" })).status).toBe(429) // spoofed XFF, same anonymous bucket
    expect((await push(app, { "X-Forwarded-For": "3.3.3.3" })).status).toBe(429)
  })

  it("backward-compat: legacy flat config + global limits push only", async () => {
    // Flat windowMs/maxRequests = implicit push rule (gated on a global rateLimit).
    const { app } = makeRouter(makeCol({ rateLimit: { maxRequests: 1 } }), { windowMs: 60_000, maxRequests: 100 })
    expect((await push(app)).status).toBe(200)
    expect((await push(app)).status).toBe(429) // push limited at flat maxRequests=1
    // pull/list stay unmetered under legacy config
    for (let i = 0; i < 3; i++) {
      expect((await app.request(PULL)).status).toBe(200)
      expect((await app.request(LIST)).status).toBe(200)
    }
  })

  it("backward-compat: flat config without a global rateLimit does NOT limit push", async () => {
    // Preserves the original gate: per-collection push limiting required a global config.
    const { app } = makeRouter(makeCol({ rateLimit: { maxRequests: 1 } }))
    for (let i = 0; i < 3; i++) expect((await push(app)).status).toBe(200)
  })

  it('composite bucket "identity+ip" keeps one budget per (identity, ip) pair', async () => {
    const { app } = makeRouter(
      makeCol({ rateLimit: { push: { windowMs: 60_000, maxRequests: 1, bucket: "identity+ip" } } }),
      undefined,
      "user-1",
      1,
    )
    expect((await push(app, { "X-Forwarded-For": "1.1.1.1" })).status).toBe(200)
    expect((await push(app, { "X-Forwarded-For": "1.1.1.1" })).status).toBe(429) // same pair exhausted
    // Same identity (resolver is constant) but a different ip → a fresh pair/budget.
    expect((await push(app, { "X-Forwarded-For": "2.2.2.2" })).status).toBe(200)
  })

  it("two-independent limits reject if EITHER the identity or the ip cap trips", async () => {
    // identity ≤ 3, ip ≤ 1, all within one window. Identity is constant across requests.
    const { app } = makeRouter(
      makeCol({
        rateLimit: {
          push: { windowMs: 60_000, identity: { maxRequests: 3 }, ip: { maxRequests: 1 } },
        },
      }),
      undefined,
      "user-1",
      1,
    )
    expect((await push(app, { "X-Forwarded-For": "1.1.1.1" })).status).toBe(200) // id#1, ip(1)#1
    expect((await push(app, { "X-Forwarded-For": "1.1.1.1" })).status).toBe(429) // ip(1) cap 1 trips
    expect((await push(app, { "X-Forwarded-For": "2.2.2.2" })).status).toBe(200) // id#3, ip(2)#1 ok
    expect((await push(app, { "X-Forwarded-For": "3.3.3.3" })).status).toBe(429) // id cap 3 now exhausted
  })
})

describe("rate-limit config validation", () => {
  it("rejects an explicit rule that cannot resolve windowMs/maxRequests", () => {
    const config: SyncConfig = {
      version: 1,
      collections: [makeCol({ rateLimit: { pull: { maxRequests: 5 } } })], // windowMs unresolved, no global
    }
    const errors = validateConfig(config)
    expect(errors.some((e) => e.includes("rateLimit.pull must resolve"))).toBe(true)
  })

  it("accepts an explicit rule that inherits windowMs from the global config", () => {
    const config: SyncConfig = {
      version: 1,
      collections: [makeCol({ rateLimit: { pull: { maxRequests: 5 } } })],
      rateLimit: { windowMs: 60_000, maxRequests: 100 },
    }
    expect(validateConfig(config)).toEqual([])
  })

  it("rejects an invalid bucket value", () => {
    const config: SyncConfig = {
      version: 1,
      collections: [makeCol({ rateLimit: { push: { windowMs: 1, maxRequests: 1, bucket: "user" as never } } })],
    }
    expect(validateConfig(config).some((e) => e.includes('bucket must be "identity"'))).toBe(true)
  })

  it('warns that bucket "ip" needs X-Forwarded-For on the TS server', () => {
    const config: SyncConfig = {
      version: 1,
      collections: [makeCol({ rateLimit: { push: { windowMs: 1, maxRequests: 1, bucket: "ip" } } })],
    }
    expect(collectConfigWarnings(config).some((w) => w.includes("IP-based bucketing"))).toBe(true)
  })

  it("rejects a rule that sets both bucket and an identity/ip sub-limit", () => {
    const config: SyncConfig = {
      version: 1,
      collections: [
        makeCol({ rateLimit: { push: { windowMs: 1, maxRequests: 1, bucket: "ip", identity: { maxRequests: 5 } } } }),
      ],
    }
    expect(validateConfig(config).some((e) => e.includes('cannot set both "bucket" and an "identity"/"ip"'))).toBe(true)
  })

  it("rejects a two-independent dimension that cannot resolve its window", () => {
    const config: SyncConfig = {
      version: 1,
      collections: [makeCol({ rateLimit: { push: { ip: { maxRequests: 5 } } } })], // no windowMs anywhere
    }
    expect(validateConfig(config).some((e) => e.includes("rateLimit.push.ip must resolve"))).toBe(true)
  })

  it("warns for an ip sub-limit (two-independent form)", () => {
    const config: SyncConfig = {
      version: 1,
      collections: [makeCol({ rateLimit: { push: { windowMs: 1, ip: { maxRequests: 1 } } } })],
    }
    expect(collectConfigWarnings(config).some((w) => w.includes("IP-based bucketing"))).toBe(true)
  })
})
