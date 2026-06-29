/**
 * Regression tests for makeHandle.push — the CAS-safe write helper.
 *
 * E1 (Bug B regression): When pull returns { data: {}, hash: "" } for a MISSING
 *   encrypted doc, decrypt must NOT be called. The mutator receives null and
 *   client.push is called with baseHash = "" (empty string, NOT null).
 *
 *   Why "": the server accepts baseHash="" on a missing doc (else: ""!="" → create)
 *   AND on a hash-less/corrupt existing doc (else: ""=="" → heal). Sending null
 *   instead deadlocks CAS when the doc is hash-less but exists on the server
 *   (base_hash is None and raw → 409 forever). See alpha.49 fix.
 *
 * E2: When pull returns a real hash, the existing doc is decrypted and passed to
 *   the mutator; baseHash carries the real hash.
 *
 * E3: hash: "" is sent as "" (not null) via ?? "" (not || null). Previously this
 *   was null due to || null (alpha.47 regression); alpha.49 reverts to ?? "" which
 *   enables the server heal path.
 *
 * E4: A hash-less-but-existing doc (hash:"", data present) also sends "" as baseHash,
 *   triggering server heal (else: ""=="" → accept).
 */
import { describe, it, expect, vi, beforeEach } from "vitest"
import type { StarfishClient, Encryptor } from "@drakkar.software/starfish-client"
import { ConflictError } from "@drakkar.software/starfish-client"
import { makeHandle } from "../src/space-access.js"
import { clearDocCache } from "../src/doc-cache.js"

beforeEach(() => clearDocCache())

function makeClient(
  pullResult: { data: Record<string, unknown>; hash: string } | null,
  peekResult?: { data: Record<string, unknown>; hash: string } | null,
): { client: StarfishClient; pushSpy: ReturnType<typeof vi.fn>; peekSpy: ReturnType<typeof vi.fn> } {
  const pushSpy = vi.fn(async () => ({ hash: "H_new", timestamp: 1 }))
  const peekSpy = vi.fn(async () => peekResult ?? null)
  const client = {
    pull: vi.fn(async () => pullResult as unknown as Record<string, unknown>),
    push: pushSpy,
    peekCache: peekSpy,
  } as unknown as StarfishClient
  return { client, pushSpy, peekSpy }
}

function makeEncryptor(): { encryptor: Encryptor; decryptSpy: ReturnType<typeof vi.fn> } {
  const decryptSpy = vi.fn(async (d: unknown) => ({ decrypted: (d as { _encrypted: string })._encrypted }))
  const encryptor = {
    decrypt: decryptSpy,
    encrypt: vi.fn(async (d: unknown) => ({ _encrypted: JSON.stringify(d) })),
  } as unknown as Encryptor
  return { encryptor, decryptSpy }
}

describe("makeHandle.push — missing encrypted doc (Bug B regression)", () => {
  it("E1: does not call decrypt when pull returns hash:'' (missing doc); baseHash is ''", async () => {
    const { client, pushSpy } = makeClient({ data: {}, hash: "" })
    const { encryptor, decryptSpy } = makeEncryptor()
    const handle = makeHandle(client, encryptor, false)
    const mutatorArg: unknown[] = []
    await handle.push("/pull/x", "/push/x", (cur) => {
      mutatorArg.push(cur)
      return { hello: "world" }
    })
    expect(decryptSpy).not.toHaveBeenCalled()
    expect(mutatorArg[0]).toBeNull()
    // '' NOT null: server heal path requires echoing "" back (else: ""=="" → accept)
    expect(pushSpy).toHaveBeenCalledWith("/push/x", expect.any(Object), "")
  })

  it("E3: baseHash is '' (not null) for a missing doc — alpha.49 fix for ?? '' vs || null", async () => {
    const { client, pushSpy } = makeClient({ data: {}, hash: "" })
    const handle = makeHandle(client, null, false)
    await handle.push("/pull/x", "/push/x", () => ({ data: 1 }))
    const [, , baseHash] = pushSpy.mock.calls[0]
    // ?? "" preserves "" (empty string); || null would have coerced it to null
    expect(baseHash).toBe("")
    expect(baseHash).not.toBeNull()
  })
})

describe("makeHandle.push — existing encrypted doc", () => {
  it("E2: decrypts existing doc and passes it to mutator; baseHash = real hash", async () => {
    const storedHash = "sha256:abc123"
    const storedEncrypted = { _encrypted: JSON.stringify({ guests: 5 }) }
    const { client, pushSpy } = makeClient({ data: storedEncrypted, hash: storedHash })
    const { encryptor, decryptSpy } = makeEncryptor()
    const handle = makeHandle(client, encryptor, false)
    const mutatorArg: unknown[] = []
    await handle.push("/pull/x", "/push/x", (cur) => {
      mutatorArg.push(cur)
      return { guests: 6 }
    })
    expect(decryptSpy).toHaveBeenCalledWith(storedEncrypted)
    expect(mutatorArg[0]).toEqual({ decrypted: JSON.stringify({ guests: 5 }) })
    expect(pushSpy).toHaveBeenCalledWith("/push/x", expect.any(Object), storedHash)
  })
})

describe("makeHandle.push — plaintext (no encryptor)", () => {
  it("passes existing data to mutator without decryption; null pull → null cur", async () => {
    const { client, pushSpy } = makeClient(null)
    const handle = makeHandle(client, null, false)
    const mutatorArg: unknown[] = []
    await handle.push("/pull/x", "/push/x", (cur) => {
      mutatorArg.push(cur)
      return { name: "test" }
    })
    expect(mutatorArg[0]).toBeNull()
    expect(pushSpy).toHaveBeenCalledWith("/push/x", { name: "test" }, "")
  })
})

describe("makeHandle.push — hash-less existing doc (E4 heal path)", () => {
  it("E4: sends baseHash='' when hash:'' but data is present (hash-less existing doc → server heal)", async () => {
    // Server stores a doc but the 'hash' field is absent/empty (corrupt envelope).
    // pull returns hash:"". The server's stored current_hash is also "".
    // Client must echo "" so server resolves: else: "" != "" → FALSE → accept (heal).
    // Sending null would hit: base_hash is None and raw → 409 forever.
    const { client, pushSpy } = makeClient({ data: { v: 2, objects: [], updatedAt: 0 }, hash: "" })
    const handle = makeHandle(client, null, false)
    await handle.push("/pull/x", "/push/x", () => ({ v: 2, objects: [{ id: "n1" }], updatedAt: 1 }))
    const [, , baseHash] = pushSpy.mock.calls[0]
    expect(baseHash).toBe("")      // "" echoed → server heals
    expect(baseHash).not.toBeNull() // null would deadlock
  })
})

describe("makeHandle.push — warm-cache (octochat-style hash persistence)", () => {
  it("H1: second push skips pull — reuses cached hash from first push success", async () => {
    const { client, pushSpy } = makeClient({ data: { existing: true }, hash: "H_initial" })
    const pullSpy = (client as unknown as { pull: ReturnType<typeof vi.fn> }).pull
    pushSpy
      .mockResolvedValueOnce({ hash: "H_after_first", timestamp: 1 })
      .mockResolvedValueOnce({ hash: "H_after_second", timestamp: 2 })

    const handle = makeHandle(client, null, false)
    await handle.push("/pull/x", "/push/x", () => ({ v: 1 }))  // cold → pulls
    await handle.push("/pull/x", "/push/x", () => ({ v: 2 }))  // warm → no pull

    expect(pullSpy).toHaveBeenCalledTimes(1)
    expect(pushSpy).toHaveBeenCalledTimes(2)
    const [, , baseHash2] = pushSpy.mock.calls[1]
    expect(baseHash2).toBe("H_after_first")  // reused from first push-success
  })

  it("H2: warm-cache 409 → re-pull + retry with authoritative hash", async () => {
    // Warm the cache with a successful first push
    const { client, pushSpy } = makeClient({ data: {}, hash: "H_initial" })
    const pullSpy = (client as unknown as { pull: ReturnType<typeof vi.fn> }).pull
    pushSpy.mockResolvedValueOnce({ hash: "H_cached", timestamp: 1 })
    const handle = makeHandle(client, null, false)
    await handle.push("/pull/x", "/push/x", () => ({ v: 1 }))
    // Cache is now warm with H_cached.

    // Second push: another device wrote → 409 ConflictError with H_fresh.
    // After 409, runCas retries with currentHash="H_fresh" → falls into cold branch → re-pulls.
    pullSpy.mockResolvedValue({ data: {}, hash: "H_fresh" })
    pushSpy
      .mockRejectedValueOnce(new ConflictError("H_fresh"))
      .mockResolvedValueOnce({ hash: "H_after_retry", timestamp: 3 })

    await handle.push("/pull/x", "/push/x", () => ({ v: 2 }))

    expect(pullSpy).toHaveBeenCalledTimes(2)   // initial + 409 retry
    const [, , retryHash] = pushSpy.mock.calls[2]
    expect(retryHash).toBe("H_fresh")           // must use authoritative conflict hash
  })

  it("H3: encrypted warm cache never stores plaintext — mutator gets null, payload is encrypted", async () => {
    const { encryptor, decryptSpy } = makeEncryptor()
    const { client, pushSpy } = makeClient({ data: { _encrypted: "secret" }, hash: "H_enc" })
    pushSpy.mockResolvedValueOnce({ hash: "H_enc_2", timestamp: 1 })
    const handle = makeHandle(client, encryptor, false)
    // First push: cold → pull → decrypt → mutate (get plaintext) → encrypt → push → cache hash only
    await handle.push("/pull/x", "/push/x", (cur) => ({ ...cur as object, updated: true }))

    // Second push: warm cache → mutator receives null (no plaintext cached), no pull, no decrypt
    const mutatorArg: unknown[] = []
    pushSpy.mockResolvedValueOnce({ hash: "H_enc_3", timestamp: 2 })
    await handle.push("/pull/x", "/push/x", (cur) => {
      mutatorArg.push(cur)
      return { replaced: true }
    })

    // Only one decrypt (from the cold-cache first call)
    expect(decryptSpy).toHaveBeenCalledTimes(1)
    // Second push: mutator got null (plaintext not cached)
    expect(mutatorArg[0]).toBeNull()
    // Second push used the cached hash
    const [, , baseHash2] = pushSpy.mock.calls[1]
    expect(baseHash2).toBe("H_enc_2")
  })
})

describe("makeHandle.push — peekCache seed (cross-reload persistence)", () => {
  it("P1: cold doc-cache + peekCache hit → push reuses persisted hash, pull never called", async () => {
    // Simulate a tab reload: doc-cache is empty, but the read-through cache has the last-known hash.
    const { client, pushSpy, peekSpy } = makeClient(
      { data: {}, hash: "H_network" },               // pull would return this (should not be called)
      { data: {}, hash: "H_persisted" },             // peekCache returns the persisted hash
    )
    const pullSpy = (client as unknown as { pull: ReturnType<typeof vi.fn> }).pull
    pushSpy.mockResolvedValueOnce({ hash: "H_after", timestamp: 1 })

    const handle = makeHandle(client, null, false)
    await handle.push("/pull/x", "/push/x", () => ({ v: 1 }))

    expect(peekSpy).toHaveBeenCalledWith("/pull/x")
    expect(pullSpy).not.toHaveBeenCalled()                     // no network pull on first push
    const [, , baseHash] = pushSpy.mock.calls[0]
    expect(baseHash).toBe("H_persisted")                       // persisted hash reused
  })

  it("P2: cold doc-cache + peekCache miss → falls back to network pull (unchanged cold path)", async () => {
    // No peek result (cache miss or no cache configured) → normal network pull.
    const { client, pushSpy } = makeClient(
      { data: {}, hash: "H_network" },   // pull returns this
      null,                               // peekCache returns null (miss)
    )
    const pullSpy = (client as unknown as { pull: ReturnType<typeof vi.fn> }).pull
    pushSpy.mockResolvedValueOnce({ hash: "H_after", timestamp: 1 })

    const handle = makeHandle(client, null, false)
    await handle.push("/pull/x", "/push/x", () => ({ v: 1 }))

    expect(pullSpy).toHaveBeenCalledTimes(1)                   // still pulls when peek misses
    const [, , baseHash] = pushSpy.mock.calls[0]
    expect(baseHash).toBe("H_network")
  })

  it("P3: encrypted doc — cold cache + peekCache hit → hash reused, plaintext never decrypted, mutator gets null", async () => {
    // Even for E2EE docs, peekCache provides the hash without decrypting the ciphertext.
    const { encryptor, decryptSpy } = makeEncryptor()
    const { client, pushSpy, peekSpy } = makeClient(
      { data: { _encrypted: "secret" }, hash: "H_net_enc" },   // pull result (should not be called)
      { data: { _encrypted: "secret_persisted" }, hash: "H_persisted_enc" }, // peekCache result
    )
    const pullSpy = (client as unknown as { pull: ReturnType<typeof vi.fn> }).pull
    pushSpy.mockResolvedValueOnce({ hash: "H_after_enc", timestamp: 1 })

    const handle = makeHandle(client, encryptor, false)
    const mutatorArgs: unknown[] = []
    await handle.push("/pull/enc", "/push/enc", (cur) => { mutatorArgs.push(cur); return { replaced: true } })

    expect(peekSpy).toHaveBeenCalled()
    expect(pullSpy).not.toHaveBeenCalled()                     // no pull
    expect(decryptSpy).not.toHaveBeenCalled()                  // no decrypt — hash only, not plaintext
    expect(mutatorArgs[0]).toBeNull()                          // mutator gets null (full-replace contract)
    const [, , baseHash] = pushSpy.mock.calls[0]
    expect(baseHash).toBe("H_persisted_enc")                   // hash from peekCache
  })
})
