# Testing Strategies

How to unit test and integration test code that uses Starfish. Every layer of the SDK is testable in isolation — no running server required.

> **Prerequisites:** [SyncManager](03-sync-manager.md), [Zustand Binding](05-state-zustand.md), [Conflict Resolution](07-conflict-resolution.md)

## Mocking StarfishClient

`SyncManager` accepts a `StarfishClient` instance, so you can pass a mock with controllable responses:

```ts
import { ConflictError, StarfishHttpError } from "@drakkar.software/starfish-client"
import type { PullResult, PushSuccess } from "@drakkar.software/starfish-client"

class MockStarfishClient {
  private pullResponse: PullResult = { data: {}, hash: "", timestamp: 0 }
  private pushResponse: PushSuccess = { hash: "abc123", timestamp: 1 }
  private pushError: Error | null = null

  pullCalls: string[] = []
  pushCalls: { path: string; data: Record<string, unknown>; baseHash: string | null }[] = []

  setPullResponse(result: PullResult) {
    this.pullResponse = result
  }

  setPushResponse(result: PushSuccess) {
    this.pushResponse = result
  }

  simulateConflict() {
    this.pushError = new ConflictError()
  }

  simulateServerError(status: number, body: string) {
    this.pushError = new StarfishHttpError(status, body)
  }

  clearErrors() {
    this.pushError = null
  }

  async pull(path: string, _checkpoint?: number): Promise<PullResult> {
    this.pullCalls.push(path)
    return this.pullResponse
  }

  async push(
    path: string,
    data: Record<string, unknown>,
    baseHash: string | null,
  ): Promise<PushSuccess> {
    this.pushCalls.push({ path, data, baseHash })
    if (this.pushError) throw this.pushError
    return this.pushResponse
  }
}
```

Use it with `SyncManager`:

```ts
import { SyncManager } from "@drakkar.software/starfish-client"

const mockClient = new MockStarfishClient()
mockClient.setPullResponse({
  data: { theme: "light" },
  hash: "abc123",
  timestamp: 1000,
})

// SyncManager accepts any object matching the StarfishClient shape
const sync = new SyncManager({
  client: mockClient as any,
  pullPath: "/pull/test",
  pushPath: "/push/test",
})

await sync.pull()
expect(sync.getData()).toEqual({ theme: "light" })
expect(sync.getHash()).toBe("abc123")
```

## Mocking SyncManager

When testing the Zustand or Legend State binding (or your integration layer), mock `SyncManager` instead of `StarfishClient`:

```ts
class MockSyncManager {
  private data: Record<string, unknown> = {}
  private hash: string | null = null
  private checkpoint = 0

  pullCount = 0
  pushCount = 0
  lastPushedData: Record<string, unknown> | null = null

  setData(data: Record<string, unknown>, hash: string, checkpoint: number) {
    this.data = data
    this.hash = hash
    this.checkpoint = checkpoint
  }

  getData() {
    return { ...this.data }
  }

  getHash() {
    return this.hash
  }

  getCheckpoint() {
    return this.checkpoint
  }

  async pull() {
    this.pullCount++
    return { data: this.data, hash: this.hash ?? "", timestamp: this.checkpoint }
  }

  async push(data: Record<string, unknown>) {
    this.pushCount++
    this.lastPushedData = data
    this.data = data
    this.hash = "pushed-hash"
    this.checkpoint = Date.now()
    return { hash: this.hash, timestamp: this.checkpoint }
  }

  async update(modifier: (current: Record<string, unknown>) => Record<string, unknown>) {
    await this.pull()
    const updated = modifier(this.data)
    return this.push(updated)
  }
}
```

## Testing Conflict Resolvers

Conflict resolvers are pure synchronous functions — ideal for unit tests. Pass known local/remote data and assert the merged result:

```ts
// Example: testing an ID-based union resolver
const resolver = (
  local: Record<string, unknown>,
  remote: Record<string, unknown>,
): Record<string, unknown> => {
  const merged: Record<string, unknown> = { ...remote }
  for (const [key, localVal] of Object.entries(local)) {
    const remoteVal = remote[key]
    if (Array.isArray(localVal) && Array.isArray(remoteVal)) {
      const byId = new Map<string, unknown>()
      for (const item of remoteVal) {
        if (item && typeof item === "object" && "id" in item) {
          byId.set((item as { id: string }).id, item)
        }
      }
      for (const item of localVal) {
        if (item && typeof item === "object" && "id" in item) {
          byId.set((item as { id: string }).id, item)
        }
      }
      merged[key] = [...byId.values()]
    }
  }
  return merged
}

// Tests
describe("ID-based union resolver", () => {
  it("merges arrays by id", () => {
    const local = { items: [{ id: "a", text: "local-a" }, { id: "c", text: "new" }] }
    const remote = { items: [{ id: "a", text: "remote-a" }, { id: "b", text: "remote-b" }] }

    const result = resolver(local, remote)

    expect(result.items).toHaveLength(3)
    // Local wins for shared IDs
    expect(result.items).toContainEqual({ id: "a", text: "local-a" })
    expect(result.items).toContainEqual({ id: "b", text: "remote-b" })
    expect(result.items).toContainEqual({ id: "c", text: "new" })
  })

  it("remote wins for non-array scalars", () => {
    const result = resolver({ theme: "dark" }, { theme: "light" })
    expect(result.theme).toBe("light")
  })
})
```

See [Conflict Resolution](07-conflict-resolution.md) for the full set of strategies to test.

## Testing Offline Behavior

Create a real Zustand store with a mock SyncManager and exercise the state machine:

```ts
import { createStarfishStore } from "@drakkar.software/starfish-client/zustand"

const mockSync = new MockSyncManager()
mockSync.setData({ theme: "light" }, "abc", 1000)

const store = createStarfishStore({
  name: "test-offline",
  syncManager: mockSync as any,
  storage: false, // disable persistence for tests
})

// 1. Go offline
store.getState().setOnline(false)
expect(store.getState().online).toBe(false)

// 2. Write while offline — dirty flag set, no push
store.getState().set((d) => ({ ...d, theme: "dark" }))
expect(store.getState().dirty).toBe(true)
expect(store.getState().data.theme).toBe("dark")
expect(mockSync.pushCount).toBe(0)

// 3. Come back online — auto-flush triggers
store.getState().setOnline(true)
// Wait for flush (async)
await new Promise((r) => setTimeout(r, 50))
expect(mockSync.pushCount).toBe(1)
expect(mockSync.lastPushedData).toEqual({ theme: "dark" })
```

### Testing persistence

Use an in-memory `StateStorage` to test persistence without touching localStorage:

```ts
function createMemoryStorage(): StateStorage & { store: Map<string, string> } {
  const store = new Map<string, string>()
  return {
    store,
    getItem: (key) => store.get(key) ?? null,
    setItem: (key, value) => { store.set(key, value) },
    removeItem: (key) => { store.delete(key) },
  }
}

const storage = createMemoryStorage()
const store = createStarfishStore({
  name: "persist-test",
  syncManager: mockSync as any,
  storage,
})

store.getState().set((d) => ({ ...d, lang: "fr" }))

// Verify data was persisted
const persisted = JSON.parse(storage.store.get("starfish-persist-test")!)
expect(persisted.state.data.lang).toBe("fr")
expect(persisted.state.dirty).toBe(true)
```

## Integration Test with Mocked Fetch

Test the full stack (real `StarfishClient` + real `SyncManager`) by injecting a mock `fetch`:

```ts
import { StarfishClient, SyncManager } from "@drakkar.software/starfish-client"

function createMockFetch(responses: Array<{ status: number; body: unknown }>) {
  let callIndex = 0
  const calls: { url: string; init?: RequestInit }[] = []

  const mockFetch = async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: url.toString(), init })
    const response = responses[callIndex++]
    return new Response(JSON.stringify(response.body), {
      status: response.status,
      headers: { "Content-Type": "application/json" },
    })
  }

  return { fetch: mockFetch as typeof globalThis.fetch, calls }
}

// Simulate: first push → 409 conflict, pull latest, retry → 200
const { fetch: mockFetch, calls } = createMockFetch([
  // Initial pull
  { status: 200, body: { data: { theme: "light" }, hash: "v1", timestamp: 1000 } },
  // First push → conflict
  { status: 409, body: { error: "hash_mismatch" } },
  // Pull after conflict
  { status: 200, body: { data: { theme: "blue", lang: "en" }, hash: "v2", timestamp: 2000 } },
  // Retry push → success
  { status: 200, body: { hash: "v3", timestamp: 3000 } },
])

const client = new StarfishClient({
  baseUrl: "https://test.local",
  fetch: mockFetch,
})

const sync = new SyncManager({
  client,
  pullPath: "/pull/settings",
  pushPath: "/push/settings",
  maxRetries: 3,
})

await sync.pull()
await sync.push({ theme: "dark" })

// Verify: 4 HTTP calls (pull, push-conflict, pull-retry, push-success)
expect(calls).toHaveLength(4)
expect(calls[1].init?.method).toBe("POST")
expect(calls[3].init?.method).toBe("POST")
```

## Testing Encryption Round-Trip

Build a one-recipient keyring + `createKeyringEncryptor` to verify
encrypt/decrypt without any network. This mirrors the v3 production path.

```ts
import {
  createKeyring,
  createKeyringEncryptor,
} from "@drakkar.software/starfish-client"
import { ed25519, x25519 } from "@noble/curves/ed25519.js"

function makeDevice() {
  const edPriv = crypto.getRandomValues(new Uint8Array(32))
  const edPub = ed25519.getPublicKey(edPriv)
  const kemPriv = crypto.getRandomValues(new Uint8Array(32))
  const kemPub = x25519.getPublicKey(kemPriv)
  const hex = (b: Uint8Array) =>
    [...b].map((x) => x.toString(16).padStart(2, "0")).join("")
  return { edPriv: hex(edPriv), edPub: hex(edPub), kemPriv: hex(kemPriv), kemPub: hex(kemPub) }
}

describe("Encryption", () => {
  it("round-trips data", async () => {
    const dev = makeDevice()
    const { keyring } = await createKeyring(
      { edPrivHex: dev.edPriv, edPubHex: dev.edPub },
      [{ subKemHex: dev.kemPub }],
    )
    const encryptor = await createKeyringEncryptor(keyring, {
      kemPubHex: dev.kemPub,
      kemPrivHex: dev.kemPriv,
    })

    const original = { items: [1, 2, 3], nested: { key: "value" } }
    const encrypted = await encryptor.encrypt(original)
    expect(encrypted).toHaveProperty("_encrypted")
    expect(encrypted).toHaveProperty("_epoch")
    expect(encrypted).not.toHaveProperty("items")

    const decrypted = await encryptor.decrypt(encrypted)
    expect(decrypted).toEqual(original)
  })

  it("a different recipient cannot decrypt", async () => {
    const alice = makeDevice()
    const bob = makeDevice()
    const { keyring } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: alice.kemPub }],
    )
    const aliceEnc = await createKeyringEncryptor(keyring, {
      kemPubHex: alice.kemPub,
      kemPrivHex: alice.kemPriv,
    })
    const sealed = await aliceEnc.encrypt({ secret: "data" })

    // Bob has no wrap entry — building an encryptor over this keyring throws.
    await expect(
      createKeyringEncryptor(keyring, { kemPubHex: bob.kemPub, kemPrivHex: bob.kemPriv }),
    ).rejects.toThrow()
    // (Even if Bob obtained the ciphertext, he has no CEK to decrypt with.)
    void sealed
  })
})
```

## Next Steps

- [Conflict Resolution](07-conflict-resolution.md) — resolver implementations to test
- [Schema Versioning](12-schema-versioning.md) — testing migration chains
- [Error Classification & Retry](15-error-retry.md) — testing error handling
