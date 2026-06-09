import { describe, it, expect, beforeAll } from "vitest"
import { webcrypto } from "node:crypto"
import {
  configurePlatform,
  getCrypto,
  ed25519Suite,
  signAppendAuthor,
  verifyAppendAuthor,
  type WriteEvent,
} from "@drakkar.software/starfish-protocol"
import {
  createSyncRouter,
  MemoryObjectStore,
  type SyncRouterOptions,
  type AuthResult,
  type SyncConfig,
  type CollectionConfig,
} from "@drakkar.software/starfish-server"
import { createWebhookHandler, openSealedDocument, isSealedBlob, generateSpaceWriteKey } from "../src/index.js"
import type { SealedBlob } from "../src/index.js"

beforeAll(() => {
  configurePlatform({
    crypto: webcrypto as unknown as Crypto,
    base64: {
      encode: (data) => Buffer.from(data).toString("base64"),
      decode: (str) => new Uint8Array(Buffer.from(str, "base64")),
    },
  })
})

const ENC = new TextEncoder()

async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await getCrypto().subtle.importKey(
    "raw",
    ENC.encode(secret) as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  )
  const sig = new Uint8Array(await getCrypto().subtle.sign("HMAC", key, ENC.encode(message) as BufferSource))
  return Array.from(sig, (b) => b.toString(16).padStart(2, "0")).join("")
}

/** Build a signed inbound webhook Request. */
async function inbound(secret: string, payload: unknown): Promise<Request> {
  const raw = JSON.stringify(payload)
  return new Request("http://host/webhook/x", {
    method: "POST",
    headers: { "content-type": "application/json", "x-webhook-signature": await hmacHex(secret, raw) },
    body: raw,
  })
}

const PUBSTREAM = "pubspaces/owner/space/streams/room"

function makeRouter(): {
  app: ReturnType<typeof createSyncRouter>
  events: WriteEvent[]
} {
  const store = new MemoryObjectStore(new Map())
  const col: CollectionConfig = {
    name: "pubstream",
    storagePath: "pubspaces/{ownerId}/{spaceId}/streams/{roomId}",
    readRoles: ["public"],
    writeRoles: ["public"],
    encryption: "none",
    appendOnly: { type: "by_timestamp" }, // requireAuthorSignature defaults to true
    maxBodyBytes: 262_144,
    allowedMimeTypes: ["application/json"],
  }
  const config: SyncConfig = { version: 1, collections: [col] }
  const events: WriteEvent[] = []
  const opts: SyncRouterOptions = {
    store,
    config,
    // Anonymous public writer (no presenter): the server verifies the stored author
    // signature but does not bind it to a request identity — exactly the webhook case.
    roleResolver: async (): Promise<AuthResult> => ({ identity: null, roles: [] }),
    plugins: [{ name: "spy", afterWrite: (e) => { events.push(e) } }],
  }
  return { app: createSyncRouter(opts), events }
}

async function pullItems(app: ReturnType<typeof createSyncRouter>): Promise<Array<{ ts: number; data: unknown; authorPubkey?: string; authorSignature?: string }>> {
  const res = await app.request(`/pull/${PUBSTREAM}?full=true`)
  const body = await res.json()
  return body.data.items
}

const author = ed25519Suite.generateSignerKeypair()
const authorKeys = { edPubHex: author.pubHex, edPrivHex: author.privHex }
const sealer = ed25519Suite.generateSignerKeypair()
const sealerKeys = { edPubHex: sealer.pubHex, edPrivHex: sealer.privHex }

/** A generic (provider-neutral) transform: lift `text`/`author` onto a chat element. */
const transform = (input: { body: unknown }) => {
  const body = input.body as { text?: unknown; author?: unknown } | undefined
  if (!body || typeof body.text !== "string") return null
  return {
    t: "msg",
    e: { id: "m-1", authorId: typeof body.author === "string" ? body.author : "webhook", text: body.text },
  }
}

describe("createWebhookHandler — forwards into the real push pipeline", () => {
  it("appends a transformed, author-signed message and fires afterWrite", async () => {
    const { app, events } = makeRouter()
    const handler = createWebhookHandler({
      routes: { hook1: { secret: "s", transform, target: `/push/${PUBSTREAM}`, author: authorKeys } },
      dispatch: (req) => app.fetch(req),
    })

    const res = await handler(await inbound("s", { text: "hello world", author: "alice" }), "hook1")
    expect(res.status).toBe(200)

    // afterWrite fired with the real WriteEvent → queuing/audit/etc. would run.
    expect(events).toHaveLength(1)
    expect(events[0]!.collection).toBe("pubstream")

    // The element is stored and its author proof verifies against the stored data.
    const items = await pullItems(app)
    expect(items).toHaveLength(1)
    const el = items[0]!
    expect(el.data).toEqual({ t: "msg", e: { id: "m-1", authorId: "alice", text: "hello world" } })
    expect(verifyAppendAuthor(PUBSTREAM, el.data as Record<string, unknown>, el.authorPubkey!, el.authorSignature!)).toBe(true)
  })

  it("Option B: seals the element so the server stores only ciphertext, openable by a member", async () => {
    const { app } = makeRouter()
    const space = generateSpaceWriteKey()
    const handler = createWebhookHandler({
      routes: {
        sealedHook: {
          secret: "s",
          transform,
          target: `/push/${PUBSTREAM}`,
          author: authorKeys,
          seal: { recipientKemPubHex: space.kemPubHex },
          sealer: sealerKeys,
        },
      },
      dispatch: (req) => app.fetch(req),
    })

    const res = await handler(await inbound("s", { text: "secret message", author: "alice" }), "sealedHook")
    expect(res.status).toBe(200)

    const items = await pullItems(app)
    const stored = items[0]!.data
    // Stored as a sealed blob — the plaintext never reaches the server.
    expect(isSealedBlob(stored)).toBe(true)
    expect(JSON.stringify(stored)).not.toContain("secret message")

    // A member with the space private key recovers the original element, with provenance pinned.
    const opened = await openSealedDocument(stored as SealedBlob, space.kemPrivHex, { requireSealer: sealer.pubHex })
    expect(opened).toEqual({ t: "msg", e: { id: "m-1", authorId: "alice", text: "secret message" } })
  })
})

describe("createWebhookHandler — rejections never reach the pipeline", () => {
  function spyHandler() {
    let dispatched = 0
    const handler = createWebhookHandler({
      routes: { hook1: { secret: "s", transform, target: `/push/${PUBSTREAM}`, author: authorKeys } },
      dispatch: async (_req) => { dispatched++; return new Response("{}", { status: 200 }) },
    })
    return { handler, dispatched: () => dispatched }
  }

  it("returns 404 for an unknown webhook id", async () => {
    const { handler, dispatched } = spyHandler()
    const res = await handler(await inbound("s", { text: "x" }), "nope")
    expect(res.status).toBe(404)
    expect(dispatched()).toBe(0)
  })

  it("returns 401 and does not forward on a bad signature", async () => {
    const { handler, dispatched } = spyHandler()
    const bad = await inbound("WRONG-SECRET", { text: "x" })
    const res = await handler(bad, "hook1")
    expect(res.status).toBe(401)
    expect(dispatched()).toBe(0)
  })

  it("returns 400 and does not forward when the transform rejects", async () => {
    const { handler, dispatched } = spyHandler()
    const res = await handler(await inbound("s", { notText: "x" }), "hook1")
    expect(res.status).toBe(400)
    expect(dispatched()).toBe(0)
  })

  it("returns 405 for a non-POST method", async () => {
    const { handler } = spyHandler()
    const req = new Request("http://host/webhook/x", { method: "GET" })
    const res = await handler(req, "hook1")
    expect(res.status).toBe(405)
  })
})

describe("createWebhookHandler — pluggable auth (no static secret)", () => {
  function bodyReq(token: string | null, payload: unknown): Request {
    const headers: Record<string, string> = { "content-type": "application/json" }
    if (token !== null) headers["x-token"] = token
    return new Request("http://host/webhook/x", { method: "POST", headers, body: JSON.stringify(payload) })
  }

  it("authenticates via a custom callback with no `secret`", async () => {
    const { app, events } = makeRouter()
    const seen: string[] = []
    const handler = createWebhookHandler({
      routes: {
        hookA: {
          // No `secret` — a custom authenticator (e.g. a per-tenant token lookup).
          authenticate: ({ headers, webhookId }) => {
            seen.push(webhookId)
            return headers["x-token"] === "let-me-in"
          },
          transform,
          target: `/push/${PUBSTREAM}`,
          author: authorKeys,
        },
      },
      dispatch: (req) => app.fetch(req),
    })

    expect((await handler(bodyReq("let-me-in", { text: "hi", author: "a" }), "hookA")).status).toBe(200)
    expect(events).toHaveLength(1)
    expect(seen).toEqual(["hookA"])
  })

  it("returns 401 when the custom authenticator rejects, and does not forward", async () => {
    let dispatched = 0
    const handler = createWebhookHandler({
      routes: { hookA: { authenticate: () => false, transform, target: `/push/${PUBSTREAM}` } },
      dispatch: async () => { dispatched++; return new Response("{}") },
    })
    expect((await handler(bodyReq("anything", { text: "x" }), "hookA")).status).toBe(401)
    expect(dispatched).toBe(0)
  })

  it("returns 500 for a route configured with neither secret nor authenticate", async () => {
    let dispatched = 0
    const handler = createWebhookHandler({
      routes: { broken: { transform, target: `/push/${PUBSTREAM}` } },
      dispatch: async () => { dispatched++; return new Response("{}") },
    })
    expect((await handler(bodyReq(null, { text: "x" }), "broken")).status).toBe(500)
    expect(dispatched).toBe(0)
  })
})
