import { describe, it, expect, vi } from "vitest"
import type { Encryptor } from "@drakkar.software/starfish-protocol"
import { StarfishClient } from "../src/client.js"
import { SyncManager } from "../src/sync.js"
import { ConflictError } from "../src/types.js"
import type { PullResponse, PushSuccess } from "../src/types.js"

// Reversible stub Encryptor: wraps the JSON payload under `_encrypted`. Verifies
// SyncManager's `encryptor` injection path (the v3 keyring path uses the same
// contract) — encrypt-on-push, decrypt-on-pull, and decrypt-on-conflict-retry.
function stubEncryptor(): Encryptor {
  return {
    async encrypt(data: Record<string, unknown>): Promise<Record<string, unknown>> {
      return { _encrypted: JSON.stringify(data) }
    },
    async decrypt(wrapper: Record<string, unknown>): Promise<Record<string, unknown>> {
      const blob = wrapper._encrypted
      if (typeof blob !== "string") {
        throw new Error("Expected encrypted data but received unencrypted document")
      }
      return JSON.parse(blob)
    },
  }
}

function mockClient(overrides: {
  pull?: (path: string, checkpoint?: number) => Promise<PullResponse>
  push?: (path: string, data: Record<string, unknown>, baseHash: string | null, sig?: string) => Promise<PushSuccess>
} = {}) {
  const client = {
    pull: overrides.pull ?? vi.fn(),
    push: overrides.push ?? vi.fn(async () => ({ hash: "h", timestamp: 1 })),
  } as unknown as StarfishClient
  return client
}

describe("SyncManager with injected encryptor", () => {
  it("decrypts remote data on pull", async () => {
    const enc = stubEncryptor()
    const original = { name: "alice", score: 42 }
    const sealed = await enc.encrypt(original)

    const client = mockClient({
      pull: vi.fn(async () => ({ data: sealed, hash: "h1", timestamp: 100 })),
    })
    const sync = new SyncManager({ client, pullPath: "/pull/t", pushPath: "/push/t", encryptor: enc })

    const result = await sync.pull()
    expect(result.data).toEqual(original)
    expect(sync.getData()).toEqual(original)
  })

  it("encrypts data before pushing", async () => {
    const enc = stubEncryptor()
    const pushFn = vi.fn(async () => ({ hash: "h2", timestamp: 200 }))
    const client = mockClient({ push: pushFn as any })
    const sync = new SyncManager({ client, pullPath: "/pull/t", pushPath: "/push/t", encryptor: enc })

    await sync.push({ secret: "value" })

    const [, sentPayload] = pushFn.mock.calls[0]
    expect(sentPayload).toEqual({ _encrypted: JSON.stringify({ secret: "value" }) })
    expect(await enc.decrypt(sentPayload as Record<string, unknown>)).toEqual({ secret: "value" })
  })

  it("decrypts remote during conflict-retry resolution", async () => {
    const enc = stubEncryptor()
    let pushCount = 0
    const pushFn = vi.fn(async () => {
      pushCount++
      if (pushCount === 1) throw new ConflictError()
      return { hash: "h2", timestamp: 200 }
    })
    const remoteSealed = await enc.encrypt({ remote: true })
    const onConflict = vi.fn((local: Record<string, unknown>, remote: Record<string, unknown>) => ({ ...remote, ...local }))

    const client = mockClient({
      pull: vi.fn(async () => ({ data: remoteSealed, hash: "new-hash", timestamp: 150 })),
      push: pushFn as any,
    })
    const sync = new SyncManager({ client, pullPath: "/pull/t", pushPath: "/push/t", encryptor: enc, onConflict })
    sync.setHash("old-hash")

    await sync.push({ local: true })

    // onConflict sees the DECRYPTED remote, not the `_encrypted` wrapper.
    expect(onConflict).toHaveBeenCalledWith({ local: true }, { remote: true })
    expect(pushCount).toBe(2)
  })
})
