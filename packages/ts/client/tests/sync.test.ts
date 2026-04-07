import { describe, it, expect, vi } from "vitest"
import { stableStringify } from "@drakkar.software/starfish-protocol"
import { StarfishClient } from "../src/client.js"
import { SyncManager } from "../src/sync.js"
import { ConflictError } from "../src/types.js"
import type { PullResponse, PushSuccess } from "../src/types.js"

function mockClient(overrides: {
  pull?: (path: string, checkpoint?: number) => Promise<PullResponse>
  push?: (path: string, data: Record<string, unknown>, baseHash: string | null, sig?: string) => Promise<PushSuccess>
} = {}) {
  const client = {
    pull: overrides.pull ?? vi.fn(async () => ({
      data: { key: "value" },
      hash: "abc123",
      timestamp: 1000,
    })),
    push: overrides.push ?? vi.fn(async () => ({
      hash: "def456",
      timestamp: 2000,
    })),
  } as unknown as StarfishClient

  return client
}

describe("SyncManager", () => {
  it("pull stores data, hash, and checkpoint", async () => {
    const client = mockClient()
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })

    const result = await sync.pull()
    expect(result.data).toEqual({ key: "value" })
    expect(sync.getData()).toEqual({ key: "value" })
    expect(sync.getHash()).toBe("abc123")
    expect(sync.getCheckpoint()).toBe(1000)
  })

  it("push sends data and updates state", async () => {
    const pushFn = vi.fn(async () => ({ hash: "new-hash", timestamp: 3000 }))
    const client = mockClient({ push: pushFn as any })
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })

    const result = await sync.push({ newKey: "newValue" })
    expect(result.hash).toBe("new-hash")
    expect(result.timestamp).toBe(3000)
    expect(sync.getHash()).toBe("new-hash")
    expect(pushFn).toHaveBeenCalledWith(
      "/push/test",
      { newKey: "newValue" },
      null,
      undefined
    )
  })

  it("incremental pull merges into local data", async () => {
    let callCount = 0
    const client = mockClient({
      pull: async () => {
        callCount++
        if (callCount === 1) {
          return { data: { a: 1, b: 2 }, hash: "h1", timestamp: 100 }
        }
        return { data: { b: 3 }, hash: "h2", timestamp: 200 }
      },
    })

    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })

    await sync.pull() // full pull
    expect(sync.getData()).toEqual({ a: 1, b: 2 })

    await sync.pull() // incremental — should merge
    expect(sync.getData()).toEqual({ a: 1, b: 3 })
  })

  it("update does pull-modify-push", async () => {
    const pushFn = vi.fn(async () => ({ hash: "updated", timestamp: 500 }))
    const client = mockClient({ push: pushFn as any })
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })

    const result = await sync.update((data) => ({
      ...data,
      extra: "field",
    }))

    expect(result.hash).toBe("updated")
    expect(pushFn).toHaveBeenCalled()
  })

  it("signData signs the encrypted payload, not the plaintext", async () => {
    const signedStrings: string[] = []
    const signData = async (data: string) => {
      signedStrings.push(data)
      return "dummy-sig"
    }

    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 1 }))
    const client = mockClient({ push: pushFn as any })

    const plaintext = { hello: "world", nested: { a: 1 } }

    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      encryptionSecret: "a]cZ#8=6gT{>w$Q}",
      encryptionSalt: "user-public-key-abc123",
      encryptionInfo: "starfish-e2e",
      signData,
    })

    await sync.push(plaintext)

    // signData was called exactly once
    expect(signedStrings).toHaveLength(1)

    // The push call's second arg is the actual payload sent to the server
    const actualPayload = pushFn.mock.calls[0][1]

    // The signed string must be stableStringify of the encrypted payload
    expect(signedStrings[0]).toBe(stableStringify(actualPayload))

    // And it must NOT be the plaintext stringification
    expect(signedStrings[0]).not.toBe(stableStringify(plaintext))

    // The payload must be an encrypted wrapper
    expect(actualPayload).toHaveProperty("_encrypted")
  })

  it("signData signs the raw data when no encryption is configured", async () => {
    const signedStrings: string[] = []
    const signData = async (data: string) => {
      signedStrings.push(data)
      return "dummy-sig"
    }

    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 1 }))
    const client = mockClient({ push: pushFn as any })

    const plaintext = { key: "value" }

    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      signData,
    })

    await sync.push(plaintext)

    expect(signedStrings).toHaveLength(1)
    // Without encryption, payload == plaintext
    expect(signedStrings[0]).toBe(stableStringify(plaintext))
  })

  it("push retries on conflict, merges via onConflict, and succeeds", async () => {
    let pushCount = 0
    const pushFn = vi.fn(async () => {
      pushCount++
      if (pushCount === 1) throw new ConflictError()
      return { hash: "merged-hash", timestamp: 3000 }
    })
    let pullCount = 0
    const pullFn = vi.fn(async () => {
      pullCount++
      if (pullCount === 1) return { data: { a: 1 }, hash: "h1", timestamp: 100 }
      // Re-pull during conflict resolution
      return { data: { a: 1, remote: true }, hash: "h2", timestamp: 200 }
    })
    const onConflict = vi.fn((local: Record<string, unknown>, remote: Record<string, unknown>) => ({
      ...remote,
      ...local,
    }))

    const client = mockClient({ pull: pullFn as any, push: pushFn as any })
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      onConflict,
    })

    await sync.pull()
    const result = await sync.push({ a: 1, local: true })

    expect(result.hash).toBe("merged-hash")
    expect(onConflict).toHaveBeenCalledWith(
      { a: 1, local: true },
      { a: 1, remote: true },
    )
    expect(pushFn).toHaveBeenCalledTimes(2)
    expect(sync.getHash()).toBe("merged-hash")
  })

  it("push throws ConflictError after exhausting maxRetries", async () => {
    const pushFn = vi.fn(async () => { throw new ConflictError() })
    const pullFn = vi.fn(async () => ({
      data: { remote: true },
      hash: "h-remote",
      timestamp: 100,
    }))

    const client = mockClient({ pull: pullFn as any, push: pushFn as any })
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      maxRetries: 1,
    })

    await sync.pull()
    await expect(sync.push({ local: true })).rejects.toThrow("hash_mismatch")
    // 1 initial + 1 retry = 2 attempts
    expect(pushFn).toHaveBeenCalledTimes(2)
  })

  it("push logs conflict resolution failure when re-pull fails", async () => {
    let pushCount = 0
    const pushFn = vi.fn(async () => {
      pushCount++
      if (pushCount === 1) throw new ConflictError()
      return { hash: "h", timestamp: 1 }
    })
    const pullFn = vi.fn(async () => {
      if (pullFn.mock.calls.length > 1) throw new Error("network down")
      return { data: {}, hash: "h1", timestamp: 100 }
    })
    const pushError = vi.fn()

    const client = mockClient({ pull: pullFn as any, push: pushFn as any })
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      logger: {
        pullStart: () => {},
        pullSuccess: () => {},
        pullError: () => {},
        pushStart: () => {},
        pushSuccess: () => {},
        pushError,
        conflict: () => {},
      },
    })

    await sync.pull()
    await expect(sync.push({ x: 1 })).rejects.toThrow("network down")
    expect(pushError).toHaveBeenCalledWith(
      expect.any(String),
      expect.stringContaining("Conflict resolution failed"),
    )
  })

  it("push forwards the signature to client.push()", async () => {
    const signData = async () => "test-signature-abc"
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 1 }))
    const client = mockClient({ push: pushFn as any })

    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      signData,
    })

    await sync.push({ foo: "bar" })

    // Fourth positional arg to client.push is the signature
    expect(pushFn.mock.calls[0][3]).toBe("test-signature-abc")
  })
})
