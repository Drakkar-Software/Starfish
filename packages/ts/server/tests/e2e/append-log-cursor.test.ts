/**
 * End-to-end integration test for `AppendLogCursor` against the REAL server.
 *
 * Everything else for the cursor is unit-tested with a mocked transport; this
 * locks the integration: the cursor builds the right `?checkpoint=` query, the
 * real server binary-searches and returns only the new tail, and a warm-started
 * cursor (seeded from persisted items) resumes correctly across "sessions".
 *
 * Wired through an in-process Hono transport (no network), mirroring
 * `full-pipeline.test.ts`. Auth is the simplest public-role setup with
 * `requireAuthorSignature: false`, since author proof is covered elsewhere.
 */

import { describe, it, expect } from "vitest"
// Relative client import (not the package name) so the e2e suite runs against
// in-tree source, not the lagging `dist/` build — see full-pipeline.test.ts.
import { StarfishClient } from "../../../client/src/client.js"
import { AppendLogCursor } from "../../../client/src/append-log.js"
import { signAppendAuthor, type Encryptor } from "@drakkar.software/starfish-protocol"
import { createSyncRouter, type SyncRouterOptions } from "../../src/router/route-builder.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import type { SyncConfig, CollectionConfig } from "../../src/config/schema.js"

function makeServer() {
  const store = new MemoryObjectStore(new Map())
  const col: CollectionConfig = {
    name: "events",
    storagePath: "events",
    readRoles: ["public"],
    writeRoles: ["public"],
    encryption: "none",
    maxBodyBytes: 65536,
    allowedMimeTypes: ["application/json"],
    appendOnly: { type: "by_timestamp", requireAuthorSignature: false },
  }
  const config: SyncConfig = { version: 1, collections: [col] }
  const opts: SyncRouterOptions = {
    store,
    config,
    // Anonymous public access — no caps/signatures needed for this test.
    roleResolver: async () => ({ identity: "anon", roles: ["public"] }),
  }
  return { app: createSyncRouter(opts), store }
}

/** In-process fetch → Hono. Adds Content-Length for POST string bodies (the
 *  server expects it), mirroring full-pipeline.test.ts. */
function fetchToApp(app: ReturnType<typeof makeServer>["app"]): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString()
    const next: RequestInit = { ...(init ?? {}) }
    if (typeof init?.body === "string" && (init.method ?? "GET").toUpperCase() === "POST") {
      const headers = new Headers(init.headers ?? {})
      if (!headers.has("Content-Length")) {
        headers.set("Content-Length", String(new TextEncoder().encode(init.body).byteLength))
      }
      next.headers = headers
    }
    return app.request(url, next)
  }) as typeof fetch
}

describe("AppendLogCursor ↔ real server (e2e)", () => {
  it("cold pull, incremental pull, and warm-resume from persisted items", async () => {
    const { app } = makeServer()
    const client = new StarfishClient({ baseUrl: "https://api.test", fetch: fetchToApp(app) })

    // Append 3 elements (server assigns strictly-increasing ts).
    for (const n of [1, 2, 3]) await client.append("/push/events", { n })

    // Cold start → first pull fetches the whole collection.
    const cursor = new AppendLogCursor({ client, pullPath: "/pull/events" })
    const batch1 = await cursor.pull()
    expect(batch1.map((e) => (e.data as { n: number }).n)).toEqual([1, 2, 3])
    expect(cursor.getItems()).toHaveLength(3)
    const cp1 = cursor.getCheckpoint()
    expect(cp1).toBe(batch1[2]!.ts)

    // Append 2 more, then pull again → ONLY the new tail (real server filtering).
    for (const n of [4, 5]) await client.append("/push/events", { n })
    const batch2 = await cursor.pull()
    expect(batch2.map((e) => (e.data as { n: number }).n)).toEqual([4, 5])
    expect(batch2.every((e) => e.ts > cp1)).toBe(true)
    expect(cursor.getItems()).toHaveLength(5)

    // Persist, simulate a fresh page: a NEW cursor seeded from the persisted log.
    const persisted = cursor.getItems()
    await client.append("/push/events", { n: 6 })
    const resumed = new AppendLogCursor({ client, pullPath: "/pull/events", initialItems: persisted })
    expect(resumed.getCheckpoint()).toBe(persisted[persisted.length - 1]!.ts)

    const batch3 = await resumed.pull()
    expect(batch3.map((e) => (e.data as { n: number }).n)).toEqual([6])
    expect(resumed.getItems()).toHaveLength(6)
    expect(resumed.getCheckpoint()).toBeGreaterThan(cp1)
  })

  it("a fresh cursor with no new elements pulls nothing", async () => {
    const { app } = makeServer()
    const client = new StarfishClient({ baseUrl: "https://api.test", fetch: fetchToApp(app) })
    await client.append("/push/events", { n: 1 })

    const cursor = new AppendLogCursor({ client, pullPath: "/pull/events" })
    await cursor.pull()
    const cp = cursor.getCheckpoint()

    const empty = await cursor.pull() // nothing appended since
    expect(empty).toEqual([])
    expect(cursor.getCheckpoint()).toBe(cp)
    expect(cursor.getItems()).toHaveLength(1)
  })

  it("verifies + decrypts a signed, encrypted append (real server requireAuthorSignature)", async () => {
    // A real Ed25519 keypair so the signature actually verifies on the server.
    const KP = {
      priv: "1133557799bbddff1133557799bbddff1133557799bbddff1133557799bbddff",
      pub: "062f2ba3c6a5590364b0864d539af151907d09ea0b741b0811e0d761a059bda4",
    }
    const enc: Encryptor = {
      encrypt: async (d) => ({ _encrypted: JSON.stringify(d) }),
      decrypt: async (w) => JSON.parse(w._encrypted as string),
    }

    // Server with author proof REQUIRED (the append-only default). The resolver
    // presents KP.pub, so an append must be authored by that key.
    const store = new MemoryObjectStore(new Map())
    const col: CollectionConfig = {
      name: "events",
      storagePath: "events",
      readRoles: ["public"],
      writeRoles: ["public"],
      encryption: "none",
      maxBodyBytes: 65536,
      allowedMimeTypes: ["application/json"],
      appendOnly: { type: "by_timestamp" }, // requireAuthorSignature defaults to true
    }
    const opts: SyncRouterOptions = {
      store,
      config: { version: 1, collections: [col] } satisfies SyncConfig,
      roleResolver: async () => ({ identity: "anon", roles: ["public"], presenter: { pubHex: KP.pub, alg: "ed25519" } }),
    }
    const app = createSyncRouter(opts)

    // Append a signed-over-ciphertext element directly. (The client-side
    // encrypt+sign+append wiring is unit-tested; here we drive the REAL server's
    // author verification, then the cursor's verify+decrypt over real storage.)
    const ciphertext = await enc.encrypt({ msg: "secret" })
    const { authorPubkey, authorSignature } = signAppendAuthor("events", ciphertext, KP.pub, KP.priv, "ed25519")
    const body = JSON.stringify({ data: ciphertext, authorPubkey, authorSignature })
    const res = await app.request("/push/events", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": String(new TextEncoder().encode(body).byteLength) },
      body,
    })
    expect(res.status).toBe(200)

    const client = new StarfishClient({ baseUrl: "https://api.test", fetch: fetchToApp(app) })
    const cursor = new AppendLogCursor({
      client,
      pullPath: "/pull/events",
      encryptor: enc,
      verifyAuthor: { expectedAuthorPubkey: KP.pub, alg: "ed25519" },
    })

    const batch = await cursor.pull()
    expect(batch).toHaveLength(1)
    // verifyAuthor passed (over the stored ciphertext) AND the data is decrypted.
    expect(batch[0]!.data).toEqual({ msg: "secret" })
    expect(batch[0]!.authorPubkey).toBe(KP.pub)
  })
})
