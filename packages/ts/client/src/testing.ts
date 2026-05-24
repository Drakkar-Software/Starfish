import type { PullResult, PushSuccess } from "@drakkar.software/starfish-protocol"
import { StarfishClient } from "./client.js"

type PullFn = (path: string, checkpoint?: number) => Promise<PullResult>
type PushFn = (path: string, data: Record<string, unknown>, baseHash: string | null) => Promise<PushSuccess>

/**
 * Creates a mock StarfishClient for testing.
 * Override individual methods or use the defaults (returns static data).
 *
 * @example
 * ```ts
 * const client = createMockClient({
 *   pull: async () => ({ data: { key: "value" }, hash: "h1", timestamp: 100 }),
 * })
 * const sync = new SyncManager({ client, pullPath: "/pull/test", pushPath: "/push/test" })
 * ```
 */
export function createMockClient(overrides?: {
  pull?: PullFn
  push?: PushFn
}): StarfishClient & { pullCalls: Array<{ path: string; checkpoint?: number }>; pushCalls: Array<{ path: string; data: Record<string, unknown>; baseHash: string | null }> } {
  const pullCalls: Array<{ path: string; checkpoint?: number }> = []
  const pushCalls: Array<{ path: string; data: Record<string, unknown>; baseHash: string | null }> = []

  const pull: PullFn = overrides?.pull ?? (async () => ({
    data: {},
    hash: "mock-hash",
    timestamp: Date.now(),
  }))

  const push: PushFn = overrides?.push ?? (async () => ({
    hash: "mock-push-hash",
    timestamp: Date.now(),
  }))

  return {
    pull: async (path: string, checkpoint?: number) => {
      pullCalls.push({ path, checkpoint })
      return pull(path, checkpoint)
    },
    push: async (path: string, data: Record<string, unknown>, baseHash: string | null) => {
      pushCalls.push({ path, data, baseHash })
      return push(path, data, baseHash)
    },
    pullCalls,
    pushCalls,
  } as unknown as StarfishClient & { pullCalls: typeof pullCalls; pushCalls: typeof pushCalls }
}

/**
 * Creates a mock fetch that returns predefined responses.
 * Useful for testing StarfishClient directly.
 *
 * @example
 * ```ts
 * const fetch = createMockFetch({ data: { key: "value" }, hash: "h1", timestamp: 100 })
 * const client = new StarfishClient({ baseUrl: "https://example.com", fetch })
 * ```
 */
export function createMockFetch(
  pullResponse?: PullResult,
  pushResponse?: PushSuccess,
): typeof globalThis.fetch {
  return async (input) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : (input as Request).url
    if (url.includes("/pull/")) {
      return new Response(JSON.stringify(pullResponse ?? { data: {}, hash: "h", timestamp: 1 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    }
    return new Response(JSON.stringify(pushResponse ?? { hash: "h", timestamp: 1 }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })
  }
}

/**
 * Creates a mock fetch that simulates a conflict (409) on the first push,
 * then succeeds on retry. Useful for testing conflict resolution.
 */
export function createConflictFetch(
  conflictPullResponse: PullResult,
  successPushResponse?: PushSuccess,
): typeof globalThis.fetch {
  let pushCount = 0
  return async (input, init?) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : (input as Request).url
    if (url.includes("/pull/")) {
      return new Response(JSON.stringify(conflictPullResponse), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    }
    pushCount++
    if (pushCount === 1) {
      return new Response(JSON.stringify({ error: "hash_mismatch" }), { status: 409 })
    }
    return new Response(JSON.stringify(successPushResponse ?? { hash: "resolved", timestamp: Date.now() }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })
  }
}
