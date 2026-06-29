/**
 * Regression tests for makeHandle.push — the CAS-safe write helper.
 *
 * E1 (Bug B regression): When pull returns { data: {}, hash: "" } for a MISSING
 *   encrypted doc, decrypt must NOT be called. The mutator must receive null and
 *   client.push must be called with baseHash = null (create semantics).
 *
 * E2: When pull returns a real hash, the existing doc is decrypted and passed to
 *   the mutator; baseHash carries the real hash.
 *
 * E3 (Bug A): hash: "" coerces to null via || null (not ?? null), so a missing
 *   doc's baseHash is always null — not "".
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
  it("E1: does not call decrypt when pull returns hash:'' (missing doc)", async () => {
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
    expect(pushSpy).toHaveBeenCalledWith("/push/x", expect.any(Object), null)
  })

  it("E3: baseHash is null (not '') for a missing doc", async () => {
    const { client, pushSpy } = makeClient({ data: {}, hash: "" })
    const handle = makeHandle(client, null, false)
    await handle.push("/pull/x", "/push/x", () => ({ data: 1 }))
    const [, , baseHash] = pushSpy.mock.calls[0]
    expect(baseHash).toBeNull()
    expect(baseHash).not.toBe("")
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
    expect(pushSpy).toHaveBeenCalledWith("/push/x", { name: "test" }, null)
  })
})
