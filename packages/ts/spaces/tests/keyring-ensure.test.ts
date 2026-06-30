/**
 * Tests for ownerEnsureKeyring — focused on the peekCache seed that prevents
 * destructive re-creation of the keyring when a degraded pull returns hash:"".
 *
 * K1: Cold/degraded pull + peekCache returns a valid keyring → keyring recovered,
 *   no createKeyring, no push, encryptor built from cached keyring.
 * K2: Cold/degraded pull + peekCache miss → createKeyring runs (existing behavior).
 * K3: Normal pull (keyring present) → peekCache not called (already warm).
 */
import { describe, it, expect, vi, beforeEach } from "vitest"
import type { StarfishClient } from "@drakkar.software/starfish-client"
import { ownerEnsureKeyring } from "../src/client.js"
import { clearDocCache } from "../src/doc-cache.js"

vi.mock("@drakkar.software/starfish-keyring", () => ({
  addCollectionRecipient: vi.fn(),
  createKeyring: vi.fn(async () => ({
    keyring: { epochs: [{ key: "NEW_EPOCH" }] },
    encryptor: { encrypt: vi.fn(), decrypt: vi.fn() },
  })),
  createKeyringEncryptor: vi.fn(async (_keyring: unknown) => ({
    encrypt: vi.fn(async (d: unknown) => d),
    decrypt: vi.fn(async (d: unknown) => d),
    _keyring,
  })),
}))

const KEYS = { edPub: "edpub", edPriv: "edpriv", kemPub: "kempub", kemPriv: "kempriv" }
const PULL = "/pull/spaces/s1/_keyring"
const PUSH = "/push/spaces/s1/_keyring"

function makeKeyringClient(
  pullResult: { data: unknown; hash: string } | null,
  peekResult?: { data: unknown; hash: string } | null,
): { client: StarfishClient; pullSpy: ReturnType<typeof vi.fn>; pushSpy: ReturnType<typeof vi.fn>; peekSpy: ReturnType<typeof vi.fn> } {
  const pullSpy = vi.fn(async () => pullResult as unknown as Record<string, unknown>)
  const pushSpy = vi.fn(async () => ({ hash: "H_new_kr", timestamp: 1 }))
  const peekSpy = vi.fn(async () => peekResult ?? null)
  const client = { pull: pullSpy, push: pushSpy, peekCache: peekSpy } as unknown as StarfishClient
  return { client, pullSpy, pushSpy, peekSpy }
}

beforeEach(() => {
  clearDocCache()
  vi.clearAllMocks()
})

describe("ownerEnsureKeyring — peekCache seed on degraded pull", () => {
  it("K1: degraded pull (hash:'', no epochs) + peekCache hit → keyring recovered, no createKeyring, no push", async () => {
    const goodKeyring = { epochs: [{ key: "EPOCH_1" }] }
    const { client, pushSpy, peekSpy } = makeKeyringClient(
      { data: {}, hash: "" },                                      // degraded server read
      { data: goodKeyring, hash: "H_cached_kr" },                  // peekCache: good keyring
    )

    const { createKeyring: createKr } = await import("@drakkar.software/starfish-keyring")
    const enc = await ownerEnsureKeyring(client, KEYS, PULL, PUSH)

    expect(peekSpy).toHaveBeenCalledWith(PULL)
    expect(createKr).not.toHaveBeenCalled()        // no destructive re-create
    expect(pushSpy).not.toHaveBeenCalled()         // no push of an empty keyring
    expect(enc).toBeTruthy()                       // encryptor built from cached keyring
  })

  it("K2: degraded pull + peekCache miss → createKeyring runs, push with empty baseHash", async () => {
    const { client, pushSpy } = makeKeyringClient(
      { data: {}, hash: "" },   // degraded
      null,                     // peekCache miss
    )

    const { createKeyring: createKr } = await import("@drakkar.software/starfish-keyring")
    await ownerEnsureKeyring(client, KEYS, PULL, PUSH)

    expect(createKr).toHaveBeenCalledTimes(1)      // creates a new keyring
    expect(pushSpy).toHaveBeenCalledTimes(1)       // pushes it
  })

  it("K3: normal pull returns keyring with epochs → peekCache not needed, no createKeyring", async () => {
    const realKeyring = { epochs: [{ key: "EPOCH_REAL" }] }
    const { client, pushSpy, peekSpy } = makeKeyringClient(
      { data: realKeyring, hash: "H_real" },    // healthy server read
    )

    const { createKeyring: createKr } = await import("@drakkar.software/starfish-keyring")
    await ownerEnsureKeyring(client, KEYS, PULL, PUSH)

    // Healthy pull short-circuits — neither peekCache nor createKeyring needed.
    expect(peekSpy).not.toHaveBeenCalled()
    expect(createKr).not.toHaveBeenCalled()
    expect(pushSpy).not.toHaveBeenCalled()
  })
})
