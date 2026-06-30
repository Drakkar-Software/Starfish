/**
 * Tests for writeProfile / ensurePseudo / ensureProfileKeys — the profile writer
 * hardening against degraded pulls (hash:"", data:null).
 *
 * W1: writeProfile degraded pull + peekCache hit → merges cached fields + good hash.
 * W2: ensurePseudo degraded pull + cached pseudo present → returns cached value, no write.
 * W3: ensureProfileKeys degraded pull + cached keys present → no re-publish.
 */
import { describe, it, expect, vi, beforeEach } from "vitest"
import type { StarfishClient } from "@drakkar.software/starfish-client"
import { writeProfile, ensurePseudo, ensureProfileKeys } from "../src/client.js"
import { defaultSpaceLayout } from "../src/layout.js"
import { clearDocCache } from "../src/doc-cache.js"

const UID = "u1"
const PULL = defaultSpaceLayout.profilePull(UID)
const PUSH = defaultSpaceLayout.profilePush(UID)

function makeProfileClient(opts: {
  pull?: () => Promise<{ data: unknown; hash: string } | null>
  push?: () => Promise<{ hash: string; timestamp: number }>
  peek?: () => Promise<{ data: unknown; hash: string } | null>
}): { client: StarfishClient; pullSpy: ReturnType<typeof vi.fn>; pushSpy: ReturnType<typeof vi.fn>; peekSpy: ReturnType<typeof vi.fn> } {
  const pullSpy = vi.fn(opts.pull ?? (async () => null))
  const pushSpy = vi.fn(opts.push ?? (async () => ({ hash: "H_new", timestamp: 1 })))
  const peekSpy = vi.fn(opts.peek ?? (async () => null))
  return {
    client: { pull: pullSpy, push: pushSpy, peekCache: peekSpy } as unknown as StarfishClient,
    pullSpy, pushSpy, peekSpy,
  }
}

beforeEach(() => {
  clearDocCache()
  vi.clearAllMocks()
})

describe("writeProfile — runCas + peekCache seed", () => {
  it("W1a: degraded pull (hash:'') + peekCache hit → merges cached fields, pushes good hash", async () => {
    const cachedData = { pseudo: "Alice", edPub: "ed1", kemPub: "kem1", kemSig: "sig1", v: 1 }
    const { client, pushSpy } = makeProfileClient({
      pull: async () => ({ data: {}, hash: "" }),                             // degraded
      peek: async () => ({ data: cachedData, hash: "H_cached" }),
    })

    await writeProfile(client, UID, defaultSpaceLayout, { pseudo: "Alice Updated" })

    expect(pushSpy).toHaveBeenCalledTimes(1)
    const [, payload, baseHash] = pushSpy.mock.calls[0]
    expect(baseHash).toBe("H_cached")                                         // good hash, not ""
    // Existing fields survive in the merge (not dropped by degraded data:{}).
    expect((payload as Record<string, unknown>).edPub).toBe("ed1")
    expect((payload as Record<string, unknown>).kemPub).toBe("kem1")
    expect((payload as Record<string, unknown>).pseudo).toBe("Alice Updated") // patch applied
  })

  it("W1b: normal pull (hash present) → no peekCache, pushes with pulled hash", async () => {
    const existing = { pseudo: "Bob", v: 1 }
    const { client, peekSpy, pushSpy } = makeProfileClient({
      pull: async () => ({ data: existing, hash: "H_live" }),
    })

    await writeProfile(client, UID, defaultSpaceLayout, { pseudo: "Bob Updated" })

    expect(peekSpy).not.toHaveBeenCalled()
    const [, , baseHash] = pushSpy.mock.calls[0]
    expect(baseHash).toBe("H_live")
  })
})

describe("ensurePseudo — peekCache guard", () => {
  it("W2a: degraded pull + cached pseudo → returns cached pseudo, no write", async () => {
    const cachedData = { pseudo: "  CachedAlice  ", v: 1 }
    const { client, pushSpy, peekSpy } = makeProfileClient({
      pull: async () => ({ data: {}, hash: "" }),                            // degraded
      peek: async () => ({ data: cachedData, hash: "H_cached" }),
    })

    const result = await ensurePseudo(client, UID, defaultSpaceLayout, "Fallback")

    expect(peekSpy).toHaveBeenCalled()
    expect(result).toBe("CachedAlice")  // trimmed cached value
    expect(pushSpy).not.toHaveBeenCalled()  // no destructive overwrite
  })

  it("W2b: degraded pull + no cache → writes fallback", async () => {
    const { client, pushSpy } = makeProfileClient({
      pull: async () => ({ data: {}, hash: "" }),    // degraded
      peek: async () => null,                         // nothing in cache
    })

    const result = await ensurePseudo(client, UID, defaultSpaceLayout, "Fallback")

    expect(result).toBe("Fallback")
    expect(pushSpy).toHaveBeenCalledTimes(1)
  })
})

describe("ensureProfileKeys — peekCache guard", () => {
  it("W3: degraded pull + cached keys present → no re-publish", async () => {
    const cachedData = { edPub: "ed_real", kemPub: "kem_real", v: 1 }
    const { client, pushSpy, peekSpy } = makeProfileClient({
      pull: async () => ({ data: {}, hash: "" }),                            // degraded
      peek: async () => ({ data: cachedData, hash: "H_cached" }),
    })

    await ensureProfileKeys(client, UID, defaultSpaceLayout, {
      edPub: "ed_new", kemPub: "kem_new", edPriv: "edpriv",
    })

    expect(peekSpy).toHaveBeenCalled()
    expect(pushSpy).not.toHaveBeenCalled()  // keys already present in cache — no re-publish
  })
})
