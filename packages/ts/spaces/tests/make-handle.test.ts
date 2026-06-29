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
import { describe, it, expect, vi } from "vitest"
import type { StarfishClient, Encryptor } from "@drakkar.software/starfish-client"
import { makeHandle } from "../src/space-access.js"

function makeClient(
  pullResult: { data: Record<string, unknown>; hash: string } | null,
): { client: StarfishClient; pushSpy: ReturnType<typeof vi.fn> } {
  const pushSpy = vi.fn(async () => ({ hash: "H_new", timestamp: 1 }))
  const client = {
    pull: vi.fn(async () => pullResult as unknown as Record<string, unknown>),
    push: pushSpy,
  } as unknown as StarfishClient
  return { client, pushSpy }
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
