import { describe, it, expect, vi } from "vitest"
import { stableStringify } from "@starfish/protocol"
import { StarfishClient } from "../src/client.js"
import { SyncManager } from "../src/sync.js"
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
