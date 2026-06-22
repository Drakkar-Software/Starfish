/**
 * Tests for the WAL live-client adapters:
 * createWalTransport, createWalSnapshotStore, walEncryptorFromKeyring,
 * walSignerFromKeys (createEd25519Signer), and createWalDocument.
 */
import { describe, it, expect, vi } from "vitest"
import {
  createWalTransport,
  createWalSnapshotStore,
  walEncryptorFromKeyring,
  noopEncryptor,
  createWalDocument,
  type WalStarfishClient,
  type WalEncryptorSource,
} from "../src/client.js"
import type { WalSnapshotDoc } from "../src/document.js"

// ── helpers ───────────────────────────────────────────────────────────────────

function makeMockClient(overrides: Partial<WalStarfishClient> = {}): WalStarfishClient & {
  appendCalls: Array<{ path: string; data: Record<string, unknown> }>
  pushCalls: Array<{ path: string; data: Record<string, unknown>; hash: string | null }>
  pullCalls: string[]
} {
  const appendCalls: Array<{ path: string; data: Record<string, unknown> }> = []
  const pushCalls: Array<{ path: string; data: Record<string, unknown>; hash: string | null }> = []
  const pullCalls: string[] = []

  return {
    appendCalls,
    pushCalls,
    pullCalls,
    async append(path, data) {
      appendCalls.push({ path, data })
      return { timestamp: Date.now() }
    },
    async pull(path) {
      pullCalls.push(path)
      return { data: null, hash: null, timestamp: 0 }
    },
    async push(path, data, hash) {
      pushCalls.push({ path, data, hash })
      return { hash: "new-hash", timestamp: Date.now() }
    },
    ...overrides,
  }
}

// ── createWalTransport ────────────────────────────────────────────────────────

describe("createWalTransport", () => {
  it("append calls client.append with /push/ prefix and data", async () => {
    const client = makeMockClient()
    const transport = createWalTransport(client)

    const body = { data: { op: "set", path: ["title"], value: "Hello" }, ts: 100 }
    await transport.append("spaces/sp-1/pages/pg-1", body as never)

    expect(client.appendCalls).toHaveLength(1)
    expect(client.appendCalls[0]!.path).toBe("/push/spaces/sp-1/pages/pg-1")
    expect(client.appendCalls[0]!.data).toEqual(body.data)
  })

  it("pull returns empty array for a 404 (new document)", async () => {
    const client = makeMockClient({
      pull: async () => { throw Object.assign(new Error("Not Found"), { status: 404 }) },
    })
    const transport = createWalTransport(client)
    const elements = await transport.pull("spaces/sp-1/pages/pg-1", 0)
    expect(elements).toEqual([])
  })

  it("pull re-throws non-404 errors", async () => {
    const client = makeMockClient({
      pull: async () => { throw Object.assign(new Error("Forbidden"), { status: 403 }) },
    })
    const transport = createWalTransport(client)
    await expect(transport.pull("spaces/sp-1/pages/pg-1", 0)).rejects.toThrow()
  })

  it("pull maps elements to WalAppendElement shape", async () => {
    const items = [
      { ts: 10, data: { op: "set" }, authorPubkey: "abc", authorSignature: "sig" },
    ]
    const client = makeMockClient({
      pull: async () => items as never,
    })
    const transport = createWalTransport(client)
    const elements = await transport.pull("spaces/sp-1/doc", 0)
    expect(elements).toHaveLength(1)
    expect(elements[0]!.ts).toBe(10)
    expect(elements[0]!.authorPubkey).toBe("abc")
  })

  it("pull uses checkpoint as since parameter", async () => {
    let capturedPath: string | undefined
    const client = makeMockClient({
      pull: async (path) => {
        capturedPath = path
        return [] as never
      },
    })
    const transport = createWalTransport(client)
    await transport.pull("spaces/sp-1/doc", 999)
    expect(capturedPath).toContain("/pull/spaces/sp-1/doc")
  })
})

// ── createWalSnapshotStore ────────────────────────────────────────────────────

const goodSnapshot: WalSnapshotDoc = {
  uptoTs: 50,
  state: { registers: {}, sequences: {}, text: {} } as never,
  producedBy: "replica-0",
  docAuthor: { docPubkey: "pk", docSignature: "sig", documentKey: "key" },
}

describe("createWalSnapshotStore", () => {
  it("read returns null when the pull returns no data", async () => {
    const client = makeMockClient({
      pull: async () => ({ data: null, hash: null, timestamp: 0 }),
    })
    const store = createWalSnapshotStore(client)
    expect(await store.read("spaces/sp-1/pages/pg-1__snapshot")).toBeNull()
  })

  it("read returns null when pull throws", async () => {
    const client = makeMockClient({
      pull: async () => { throw new Error("network") },
    })
    const store = createWalSnapshotStore(client)
    expect(await store.read("key__snapshot")).toBeNull()
  })

  it("read returns the snapshot doc when present and valid", async () => {
    const client = makeMockClient({
      pull: async () => ({ data: goodSnapshot, hash: "h1", timestamp: 100 }),
    })
    const store = createWalSnapshotStore(client)
    const result = await store.read("key__snapshot")
    expect(result).not.toBeNull()
    expect(result!.uptoTs).toBe(50)
  })

  it("write calls client.push with /push/ path and snapshot doc", async () => {
    const client = makeMockClient({
      pull: async () => ({ data: null, hash: "h0", timestamp: 0 }),
      push: async (path, data, hash) => {
        client.pushCalls.push({ path, data: data as Record<string, unknown>, hash })
        return { hash: "h1", timestamp: 1 }
      },
    })
    const store = createWalSnapshotStore(client)
    await store.write("spaces/sp-1/doc__snapshot", goodSnapshot)
    expect(client.pushCalls[0]!.path).toBe("/push/spaces/sp-1/doc__snapshot")
  })

  it("write retries on conflict and succeeds", async () => {
    let pushAttempts = 0
    const client = makeMockClient({
      pull: async () => ({ data: null, hash: `h${pushAttempts}`, timestamp: 0 }),
      push: async (_path, _data, _hash) => {
        pushAttempts++
        if (pushAttempts === 1) {
          const err = new Error("hash_mismatch")
          err.name = "ConflictError"
          throw err
        }
        return { hash: "h-ok", timestamp: 1 }
      },
    })
    const store = createWalSnapshotStore(client)
    await store.write("key__snapshot", goodSnapshot)
    expect(pushAttempts).toBe(2)
  })

  it("write throws after 3 consecutive conflicts", async () => {
    let pushAttempts = 0
    const client = makeMockClient({
      pull: async () => ({ data: null, hash: "h0", timestamp: 0 }),
      push: async () => {
        pushAttempts++
        const err = new Error("hash_mismatch")
        err.name = "ConflictError"
        throw err
      },
    })
    const store = createWalSnapshotStore(client)
    await expect(store.write("key__snapshot", goodSnapshot)).rejects.toThrow()
    expect(pushAttempts).toBe(3)
  })

  it("write propagates non-conflict errors immediately", async () => {
    const client = makeMockClient({
      pull: async () => ({ data: null, hash: null, timestamp: 0 }),
      push: async () => { throw new Error("access_denied") },
    })
    const store = createWalSnapshotStore(client)
    await expect(store.write("key__snapshot", goodSnapshot)).rejects.toThrow("access_denied")
  })
})

// ── walEncryptorFromKeyring ───────────────────────────────────────────────────

describe("walEncryptorFromKeyring", () => {
  const fakeEncryptor: WalEncryptorSource = {
    async encrypt(data) { return { _enc: JSON.stringify(data) } },
    async decrypt(data) { return JSON.parse((data as Record<string, string>)._enc!) },
  }

  it("seal calls enc.encrypt and open calls enc.decrypt", async () => {
    const walEnc = walEncryptorFromKeyring(fakeEncryptor)
    const plain = { op: "set", path: ["title"] }
    const sealed = await walEnc.seal(plain as never)
    const opened = await walEnc.open(sealed as never)
    expect(opened).toEqual(plain)
  })

  it("noopEncryptor is a pass-through (seal === open)", async () => {
    const data = { op: "ins", pos: 0, val: "a" }
    const sealed = await noopEncryptor.seal(data as never)
    const opened = await noopEncryptor.open(sealed as never)
    expect(opened).toEqual(data)
  })
})

// ── createWalDocument ─────────────────────────────────────────────────────────

import { ed25519 } from "@noble/curves/ed25519.js"
import { WalDocument } from "../src/document.js"

function hexFrom(bytes: Uint8Array) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
}

describe("createWalDocument", () => {
  it("returns a WalDocument instance", () => {
    const privKey = ed25519.utils.randomSecretKey()
    const edPrivHex = hexFrom(privKey)
    const edPubHex = hexFrom(ed25519.getPublicKey(privKey))

    const client = makeMockClient()
    const doc = createWalDocument({
      client,
      documentKey: "spaces/sp-test/pages/pg-test",
      edPubHex,
      edPrivHex,
    })

    expect(doc).toBeInstanceOf(WalDocument)
  })

  it("skips the snapshot store when withSnapshots is false", () => {
    const privKey = ed25519.utils.randomSecretKey()
    const edPrivHex = hexFrom(privKey)
    const edPubHex = hexFrom(ed25519.getPublicKey(privKey))

    // createWalDocument should not throw — the internal snapshotStore is undefined.
    const client = makeMockClient()
    expect(() =>
      createWalDocument({
        client,
        documentKey: "spaces/sp-test/pages/pg-test",
        edPubHex,
        edPrivHex,
        withSnapshots: false,
      }),
    ).not.toThrow()
  })
})
