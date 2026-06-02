import { describe, it, expect } from "vitest"
import { webcrypto } from "node:crypto"
import { readFileSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import {
  configurePlatform,
  computeHash,
  signAppendAuthor,
  verifyAppendAuthor,
} from "@drakkar.software/starfish-protocol"
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

// A fixed Ed25519 keypair used by the mechanics tests below: `makeRouter`
// advertises its pubkey as the request presenter and the `push` helper signs
// every element with it, so author proof (enforced by default) is satisfied
// transparently. The negative/enforcement cases live in their own describe.
const SIGNER = {
  priv: "1133557799bbddff1133557799bbddff1133557799bbddff1133557799bbddff",
  pub: "062f2ba3c6a5590364b0864d539af151907d09ea0b741b0811e0d761a059bda4",
}

function makeRouter(col: CollectionConfig) {
  const store = new MemoryObjectStore(new Map())
  const config: SyncConfig = { version: 1, collections: [col] }
  const opts: SyncRouterOptions = {
    store,
    config,
    roleResolver: async (): Promise<AuthResult> => ({
      identity: "user-1",
      roles: ["admin"],
      presenter: { pubHex: SIGNER.pub, alg: "ed25519" },
    }),
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
  // Sign the element so the default `requireAuthorSignature` is satisfied. The
  // signature is over the element data only (independent of `ts`/`baseHash`).
  // Skip for a non-object item — the server rejects that at the data check
  // before author verification, which is what those tests assert.
  if (item != null && typeof item === "object" && !Array.isArray(item)) {
    const { authorPubkey, authorSignature } = signAppendAuthor("events",
      item as Record<string, unknown>,
      SIGNER.pub,
      SIGNER.priv,
      "ed25519",
    )
    body["authorPubkey"] = authorPubkey
    body["authorSignature"] = authorSignature
  }
  return app.request("/push/events", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  })
}

async function pull(app: ReturnType<typeof createSyncRouter>, checkpoint?: number) {
  // A pull must declare a bound; no checkpoint → explicit full fetch.
  const url = checkpoint != null ? `/pull/events?checkpoint=${checkpoint}` : "/pull/events?full=true"
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

describe("appendOnly pull bounding (limit / full / required bound)", () => {
  async function seed(app: ReturnType<typeof createSyncRouter>) {
    for (let n = 1; n <= 5; n++) await push(app, { n }, { ts: n * 10 })
  }

  it("rejects an unbounded pull (no checkpoint/limit/last/full) with 400 pull_bound_required", async () => {
    const { app } = makeRouter(makeCol())
    await seed(app)
    const res = await app.request("/pull/events")
    expect(res.status).toBe(400)
    expect((await res.json()).error).toBe("pull_bound_required")
  })

  it("accepts each bound individually: checkpoint, limit, last, full", async () => {
    const { app } = makeRouter(makeCol())
    await seed(app)
    for (const q of ["checkpoint=0", "limit=2", "last=2", "full=true"]) {
      expect((await app.request(`/pull/events?${q}`)).status).toBe(200)
    }
  })

  it("?limit=K is an alias of ?last=K (identical items)", async () => {
    const { app } = makeRouter(makeCol())
    await seed(app)
    const byLimit = await (await app.request("/pull/events?limit=2")).json()
    const byLast = await (await app.request("/pull/events?last=2")).json()
    expect(byLimit.data.items).toEqual(byLast.data.items)
    expect(payloads(byLimit.data.items)).toEqual([{ n: 4 }, { n: 5 }])
  })

  it("when both ?limit and ?last are given, limit wins", async () => {
    const { app } = makeRouter(makeCol())
    await seed(app)
    const body = await (await app.request("/pull/events?limit=1&last=4")).json()
    expect(payloads(body.data.items)).toEqual([{ n: 5 }])
  })

  it("?limit=0 returns empty; ?limit >= count returns all", async () => {
    const { app } = makeRouter(makeCol())
    await seed(app)
    expect((await (await app.request("/pull/events?limit=0")).json()).data.items).toEqual([])
    const all = await (await app.request("/pull/events?limit=100")).json()
    expect(all.data.items).toHaveLength(5)
  })

  it("?full=true combined with a bound returns 400 full_with_bounds", async () => {
    const { app } = makeRouter(makeCol())
    await seed(app)
    for (const q of ["full=true&checkpoint=0", "full=true&limit=2", "full=true&last=2"]) {
      const res = await app.request(`/pull/events?${q}`)
      expect(res.status).toBe(400)
      expect((await res.json()).error).toBe("full_with_bounds")
    }
  })

  it("?full=true is rejected 400 full_not_allowed when allowFull:false", async () => {
    const { app } = makeRouter(makeCol({ appendOnly: { type: "by_timestamp", allowFull: false } }))
    await seed(app)
    const res = await app.request("/pull/events?full=true")
    expect(res.status).toBe(400)
    expect((await res.json()).error).toBe("full_not_allowed")
    // a bounded pull still works
    expect((await app.request("/pull/events?limit=2")).status).toBe(200)
  })

  it("?limit above maxPullLimit is clamped down", async () => {
    const { app } = makeRouter(makeCol({ appendOnly: { type: "by_timestamp", maxPullLimit: 2 } }))
    await seed(app)
    const body = await (await app.request("/pull/events?limit=100")).json()
    expect(payloads(body.data.items)).toEqual([{ n: 4 }, { n: 5 }])
  })

  it("a checkpoint older than maxCheckpointAgeMs returns 400 checkpoint_too_old", async () => {
    const { app } = makeRouter(makeCol({ appendOnly: { type: "by_timestamp", maxCheckpointAgeMs: 60_000 } }))
    await seed(app)
    // ts=10 is epoch-old → far beyond the 60s window
    const old = await app.request("/pull/events?checkpoint=10")
    expect(old.status).toBe(400)
    expect((await old.json()).error).toBe("checkpoint_too_old")
    // a recent checkpoint (within the window) is accepted
    const recent = await app.request(`/pull/events?checkpoint=${Date.now() - 1000}`)
    expect(recent.status).toBe(200)
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

describe("appendOnly author proof (requireAuthorSignature, default on)", () => {
  // `OTHER` is an unrelated keypair used for the impersonation case (a valid
  // signature, but by a key that is NOT the request presenter).
  const OTHER = {
    priv: "99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa",
    pub: "01e3bf84a66206793b37113dfa7c682573d748d93f7328d76375cde6f11a622f",
  }

  // A router whose resolver advertises `presenterPub` as the verified request
  // presenter (the cap-cert resolver does this in production). Author proof is
  // enforced by default — the override carries no `requireAuthorSignature`.
  function makeAuthorRouter(presenterPub: string | null = SIGNER.pub) {
    const store = new MemoryObjectStore(new Map())
    const config: SyncConfig = { version: 1, collections: [makeCol()] }
    const opts: SyncRouterOptions = {
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({
        identity: "user-1",
        roles: ["admin"],
        ...(presenterPub ? { presenter: { pubHex: presenterPub, alg: "ed25519" as const } } : {}),
      }),
    }
    return { app: createSyncRouter(opts), store }
  }

  function postBody(app: ReturnType<typeof createSyncRouter>, body: Record<string, unknown>) {
    return app.request("/push/events", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
  }

  it("accepts a validly-signed append and stores the author proof on the element", async () => {
    const { app } = makeAuthorRouter()
    const item = { msg: "signed hello" }
    const { authorPubkey, authorSignature } = signAppendAuthor("events",item, SIGNER.pub, SIGNER.priv, "ed25519")
    expect((await postBody(app, { data: item, authorPubkey, authorSignature })).status).toBe(200)

    const body = await (await pull(app)).json()
    const el = body.data.items[0] as { data: Record<string, unknown>; authorPubkey: string; authorSignature: string }
    expect(el.authorPubkey).toBe(SIGNER.pub)
    // The stored proof re-verifies against the stored element data.
    expect(verifyAppendAuthor("events", el.data, el.authorPubkey, el.authorSignature, "ed25519")).toBe(true)
  })

  it("rejects an append carrying no author proof (400)", async () => {
    const { app } = makeAuthorRouter()
    expect((await postBody(app, { data: { msg: "x" } })).status).toBe(400)
  })

  it("rejects an append whose author is not the request presenter — impersonation (403)", async () => {
    // Validly signed by OTHER, but the presenter is SIGNER.
    const item = { msg: "i am the presenter, honest" }
    const { authorPubkey, authorSignature } = signAppendAuthor("events",item, OTHER.pub, OTHER.priv, "ed25519")
    const { app } = makeAuthorRouter(SIGNER.pub)
    expect((await postBody(app, { data: item, authorPubkey, authorSignature })).status).toBe(403)
  })

  it("rejects a tampered signature (403)", async () => {
    const { app } = makeAuthorRouter()
    const item = { msg: "tamper me" }
    const { authorSignature } = signAppendAuthor("events",item, SIGNER.pub, SIGNER.priv, "ed25519")
    const bad = (authorSignature[0] === "A" ? "B" : "A") + authorSignature.slice(1)
    expect((await postBody(app, { data: item, authorPubkey: SIGNER.pub, authorSignature: bad })).status).toBe(403)
  })

  it("rejects a signature made over different data than the stored item (403)", async () => {
    const { app } = makeAuthorRouter()
    // Sign one object, send another → the server verifies over the sent item.
    const { authorPubkey, authorSignature } = signAppendAuthor("events",{ msg: "original" }, SIGNER.pub, SIGNER.priv, "ed25519")
    expect((await postBody(app, { data: { msg: "swapped" }, authorPubkey, authorSignature })).status).toBe(403)
  })

  it("requireAuthorSignature:false accepts an unsigned append (opt-out)", async () => {
    const store = new MemoryObjectStore(new Map())
    const col = makeCol({ appendOnly: { type: "by_timestamp", requireAuthorSignature: false } })
    const opts: SyncRouterOptions = {
      store,
      config: { version: 1, collections: [col] },
      roleResolver: async (): Promise<AuthResult> => ({ identity: "user-1", roles: ["admin"] }),
    }
    const app = createSyncRouter(opts)
    expect((await postBody(app, { data: { msg: "no sig needed" } })).status).toBe(200)
  })
})
