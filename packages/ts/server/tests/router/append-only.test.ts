import { describe, it, expect } from "vitest"
import { webcrypto } from "node:crypto"
import { readFileSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import { configurePlatform, computeHash } from "@drakkar.software/starfish-protocol"
import { createKeyring, createKeyringEncryptor } from "@drakkar.software/starfish-keyring"
import { createSyncRouter, type SyncRouterOptions, type AuthResult } from "../../src/router/route-builder.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import type { SyncConfig, CollectionConfig } from "../../src/config/schema.js"
import { validateConfig } from "../../src/config/validate.js"

// Ready-made Ed25519 + X25519 keypairs for the real-keyring round-trip test.
const FIXTURES = JSON.parse(
  readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), "../../../../../tests/test-vectors/multi-recipient-wrap.json"),
    "utf-8",
  ),
).fixtures as Record<string, { edPriv: string; edPub: string; kemPriv: string; kemPub: string }>

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

function makeCol(overrides: Partial<CollectionConfig> = {}): CollectionConfig {
  return {
    name: "events",
    storagePath: "events",
    readRoles: ["admin"],
    writeRoles: ["admin"],
    encryption: "none",
    maxBodyBytes: 65536,
    allowedMimeTypes: ["application/json"],
    appendOnly: { type: "by_timestamp" },
    ...overrides,
  }
}

function makeRouter(col: CollectionConfig) {
  const store = new MemoryObjectStore(new Map())
  const config: SyncConfig = { version: 1, collections: [col] }
  const opts: SyncRouterOptions = {
    store,
    config,
    roleResolver: async (): Promise<AuthResult> => ({ identity: "user-1", roles: ["admin"] }),
  }
  return { app: createSyncRouter(opts), store }
}

/** Push an element. `ts` (optional) sends a client-supplied element timestamp. */
async function push(
  app: ReturnType<typeof createSyncRouter>,
  item: unknown,
  opts: { baseHash?: string | null; ts?: number } = {},
) {
  const body: Record<string, unknown> = { data: item }
  if (opts.baseHash !== undefined) body["baseHash"] = opts.baseHash
  if (opts.ts !== undefined) body["ts"] = opts.ts
  return app.request("/push/events", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  })
}

async function pull(app: ReturnType<typeof createSyncRouter>, checkpoint?: number) {
  const url = checkpoint != null ? `/pull/events?checkpoint=${checkpoint}` : "/pull/events"
  return app.request(url)
}

/** Extract the element payloads (drop the `{ts}` envelope) from a pulled array. */
function payloads(arr: unknown): unknown[] {
  return (arr as Array<{ ts: number; data: unknown }>).map((e) => e.data)
}

describe("appendOnly persist=true (stored {ts,data} array)", () => {
  it("first push creates a one-element array, returns 200", async () => {
    const { app } = makeRouter(makeCol())
    const res = await push(app, { msg: "hello" })
    expect(res.status).toBe(200)
  })

  it("two sequential pushes → 2 elements in order, each {ts, data}", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { msg: "first" })
    await push(app, { msg: "second" })
    const body = await (await pull(app)).json()
    expect(payloads(body.data.items)).toEqual([{ msg: "first" }, { msg: "second" }])
    for (const el of body.data.items) expect(typeof el.ts).toBe("number")
    expect(body.data.items[1].ts).toBeGreaterThan(body.data.items[0].ts)
  })

  it("client baseHash is ignored (no hash check, no 409)", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { msg: "first" })
    const res = await push(app, { msg: "second" }, { baseHash: "wrong-hash-doesnt-matter" })
    expect(res.status).toBe(200)
  })

  it("custom appendField stores under that key", async () => {
    const { app } = makeRouter(makeCol({ appendOnly: { type: "by_timestamp", field: "logs" } }))
    await push(app, { msg: "entry" })
    const body = await (await pull(app)).json()
    expect(payloads(body.data.logs)).toEqual([{ msg: "entry" }])
    expect(body.data.items).toBeUndefined()
  })
})

describe("appendOnly client-supplied timestamps", () => {
  it("provided ts is stored verbatim and returned", async () => {
    const { app } = makeRouter(makeCol())
    const res = await push(app, { n: 1 }, { ts: 1000 })
    const body = await res.json()
    expect(body.timestamp).toBe(1000)
    const pulled = await (await pull(app)).json()
    expect(pulled.data.items[0].ts).toBe(1000)
  })

  it("provided ts must be strictly greater than latest (equal → 409)", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 }, { ts: 1000 })
    const res = await push(app, { n: 2 }, { ts: 1000 })
    expect(res.status).toBe(409)
    const body = await res.json()
    expect(body.error).toBe("non_monotonic_timestamp")
  })

  it("provided ts less than latest → 409", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 }, { ts: 1000 })
    const res = await push(app, { n: 2 }, { ts: 500 })
    expect(res.status).toBe(409)
  })

  it("provided ts greater than latest → accepted", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 }, { ts: 1000 })
    const res = await push(app, { n: 2 }, { ts: 2000 })
    expect(res.status).toBe(200)
  })

  it("non-integer ts → 400", async () => {
    const { app } = makeRouter(makeCol())
    const res = await push(app, { n: 1 }, { ts: 1.5 })
    expect(res.status).toBe(400)
  })

  it("ts too far in the future → 400 (can't poison the monotonic counter)", async () => {
    const { app } = makeRouter(makeCol())
    const res = await push(app, { n: 1 }, { ts: Date.now() + 3_600_000 }) // +1h ≫ 5m skew
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toMatch(/future/)
  })

  it("ts within the future skew window → accepted", async () => {
    const { app } = makeRouter(makeCol())
    const res = await push(app, { n: 1 }, { ts: Date.now() + 60_000 }) // +1m < 5m skew
    expect(res.status).toBe(200)
  })

  it("409 conflict body does not leak the latest timestamp", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 }, { ts: 1000 })
    const res = await push(app, { n: 2 }, { ts: 500 })
    expect(res.status).toBe(409)
    const body = await res.json()
    expect(body).toEqual({ error: "non_monotonic_timestamp" })
    expect(body.latest).toBeUndefined()
  })
})

describe("appendOnly stored hash semantics (length-tagged)", () => {
  it("push response hash equals computeHash({ n, last })", async () => {
    const { app } = makeRouter(makeCol())
    const item = { msg: "hello" }
    const body = await (await push(app, item)).json()
    expect(body.hash).toBe(await computeHash({ n: 1, last: item }))
  })

  it("duplicate item push produces a different hash (length changes)", async () => {
    const { app } = makeRouter(makeCol())
    const item = { msg: "same" }
    const r1 = await (await push(app, item)).json()
    const r2 = await (await push(app, item)).json()
    expect(r1.hash).not.toBe(r2.hash)
  })
})

describe("appendOnly checkpoint pull", () => {
  it("?checkpoint=0 returns full array", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 })
    await push(app, { n: 2 })
    await push(app, { n: 3 })
    const body = await (await pull(app, 0)).json()
    expect(payloads(body.data.items)).toEqual([{ n: 1 }, { n: 2 }, { n: 3 }])
  })

  it("checkpoint after 2nd element returns only the 3rd", async () => {
    // Explicit timestamps keep this deterministic — auto-ts uses max(now, latest+1),
    // so back-to-back appends in the same millisecond can bump past a wall-clock
    // checkpoint captured between them.
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 }, { ts: 100 })
    await push(app, { n: 2 }, { ts: 200 })
    await push(app, { n: 3 }, { ts: 300 })
    const body = await (await pull(app, 200)).json()
    expect(payloads(body.data.items)).toEqual([{ n: 3 }])
  })

  it("checkpoint after all pushes returns empty array", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 })
    await push(app, { n: 2 })
    const after = Date.now() + 1000
    const body = await (await pull(app, after)).json()
    expect(body.data.items).toEqual([])
  })

  it("checkpoint works with client-supplied timestamps", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 }, { ts: 100 })
    await push(app, { n: 2 }, { ts: 200 })
    await push(app, { n: 3 }, { ts: 300 })
    const body = await (await pull(app, 150)).json()
    expect(payloads(body.data.items)).toEqual([{ n: 2 }, { n: 3 }])
  })
})

describe("appendOnly ?last=K pull", () => {
  it("?last=2 on 3-element array returns last 2", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 })
    await push(app, { n: 2 })
    await push(app, { n: 3 })
    const body = await (await app.request("/pull/events?last=2")).json()
    expect(payloads(body.data.items)).toEqual([{ n: 2 }, { n: 3 }])
  })

  it("?last=0 returns empty array", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 })
    await push(app, { n: 2 })
    const body = await (await app.request("/pull/events?last=0")).json()
    expect(body.data.items).toEqual([])
  })

  it("?last larger than length returns full array", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 })
    await push(app, { n: 2 })
    const body = await (await app.request("/pull/events?last=100")).json()
    expect(payloads(body.data.items)).toEqual([{ n: 1 }, { n: 2 }])
  })

  it("?checkpoint then ?last: checkpoint filters first, then last K", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 }, { ts: 10 })
    await push(app, { n: 2 }, { ts: 20 })
    await push(app, { n: 3 }, { ts: 30 })
    await push(app, { n: 4 }, { ts: 40 })
    await push(app, { n: 5 }, { ts: 50 })
    const body = await (await app.request(`/pull/events?checkpoint=20&last=2`)).json()
    expect(payloads(body.data.items)).toEqual([{ n: 4 }, { n: 5 }])
  })

  it("invalid ?last (non-integer) returns 400", async () => {
    const { app } = makeRouter(makeCol())
    const res = await app.request("/pull/events?last=abc")
    expect(res.status).toBe(400)
  })

  it("negative ?last returns 400", async () => {
    const { app } = makeRouter(makeCol())
    const res = await app.request("/pull/events?last=-1")
    expect(res.status).toBe(400)
  })
})

describe("appendOnly delegated encryption (real keyring round-trip)", () => {
  // Build a real per-collection keyring + encryptor (not a stub), so this proves
  // encrypt → push → store-opaque → pull → decrypt actually works end-to-end and
  // that the server filters by the plaintext `ts` without reading the ciphertext.
  async function makeEncryptor() {
    const adder = FIXTURES.alice_root
    const dev = FIXTURES.alice_dev_1
    const { keyring } = await createKeyring(
      { edPrivHex: adder.edPriv, edPubHex: adder.edPub },
      [{ subKemHex: dev.kemPub }],
    )
    return createKeyringEncryptor(
      keyring,
      { kemPubHex: dev.kemPub, kemPrivHex: dev.kemPriv },
      { trustedAdders: [adder.edPub] },
    )
  }

  it("round-trips a keyring-encrypted element through push/pull/decrypt", async () => {
    const { app } = makeRouter(makeCol({ encryption: "delegated" }))
    const enc = await makeEncryptor()

    const sealed = await enc.encrypt({ secret: "alpha", n: 1 })
    expect(typeof sealed._encrypted).toBe("string") // real ciphertext, not plaintext

    const res = await push(app, sealed as Record<string, unknown>)
    expect(res.status).toBe(200)

    const body = await (await pull(app)).json()
    const storedEl = body.data.items[0]
    expect(typeof storedEl.ts).toBe("number")
    // The server stored the ciphertext opaquely — the plaintext is NOT visible.
    expect(JSON.stringify(storedEl.data)).not.toContain("alpha")

    const decrypted = await enc.decrypt(storedEl.data as Record<string, unknown>)
    expect(decrypted).toEqual({ secret: "alpha", n: 1 })
  })

  it("checkpoint filters encrypted elements by plaintext ts; survivors still decrypt", async () => {
    const { app } = makeRouter(makeCol({ encryption: "delegated" }))
    const enc = await makeEncryptor()

    await push(app, (await enc.encrypt({ secret: "one" })) as Record<string, unknown>, { ts: 100 })
    await push(app, (await enc.encrypt({ secret: "two" })) as Record<string, unknown>, { ts: 200 })

    const body = await (await pull(app, 150)).json()
    expect(body.data.items).toHaveLength(1)
    expect(body.data.items[0].ts).toBe(200)
    const decrypted = await enc.decrypt(body.data.items[0].data as Record<string, unknown>)
    expect(decrypted).toEqual({ secret: "two" })
  })
})

describe("appendOnly concurrency (no hash check)", () => {
  it("two concurrent pushes both land", async () => {
    const { app } = makeRouter(makeCol())
    const [r1, r2] = await Promise.all([push(app, { n: 1 }), push(app, { n: 2 })])
    expect([r1.status, r2.status]).toEqual([200, 200])
    const body = await (await pull(app)).json()
    expect(body.data.items).toHaveLength(2)
    expect(body.data.items[1].ts).toBeGreaterThan(body.data.items[0].ts)
  })
})

describe("appendOnly config validation", () => {
  it("valid appendOnly (persist=true default) passes", () => {
    const errors = validateConfig({ version: 1, collections: [makeCol()] })
    expect(errors).toHaveLength(0)
  })

  it("appendOnly with delegated encryption is now ACCEPTED", () => {
    const errors = validateConfig({
      version: 1,
      collections: [makeCol({ encryption: "delegated" })],
    })
    expect(errors).toHaveLength(0)
  })

  it("unknown appendOnly.type is rejected", () => {
    const errors = validateConfig({
      version: 1,
      collections: [makeCol({ appendOnly: { type: "by_sequence" as any } })],
    })
    expect(errors.some((e) => e.includes("by_sequence") || e.includes("not supported"))).toBe(true)
  })

  it("appendOnly with bundle is rejected", () => {
    const errors = validateConfig({
      version: 1,
      collections: [
        makeCol({ bundle: "myBundle", storagePath: "events/{identity}", encryption: "none" }),
      ],
    })
    expect(errors.some((e) => e.includes("bundle"))).toBe(true)
  })
})
