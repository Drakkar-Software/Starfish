import { describe, it, expect, vi } from "vitest"
import { S3ObjectStore } from "../../src/storage/s3.js"

// Regression for the segmented append-only log: `listKeys` must return EVERY
// key under a prefix, not just the first S3 page (≤1000 keys). A truncated
// first page would silently drop chunks past the 1000th and the checkpoint
// bisect would read incomplete data.

interface Page {
  keys: string[]
  next?: string
}

function makeStore(pages: Page[]) {
  const store = new S3ObjectStore({
    accessKeyId: "x",
    secretAccessKey: "y",
    endpoint: "http://localhost:9000",
    bucket: "b",
  })
  const calls: Record<string, unknown>[] = []
  let i = 0
  ;(store as unknown as { _client: { send: unknown } })._client = {
    send: vi.fn(async (cmd: { input: Record<string, unknown> }) => {
      calls.push(cmd.input)
      const page = pages[i++]!
      return {
        Contents: page.keys.map((Key) => ({ Key })),
        IsTruncated: page.next != null,
        NextContinuationToken: page.next,
      }
    }),
  }
  return { store, calls }
}

describe("S3ObjectStore.listKeys pagination", () => {
  it("follows the continuation token across pages and returns all keys", async () => {
    const { store, calls } = makeStore([
      { keys: ["a/1", "a/2"], next: "TOKEN1" },
      { keys: ["a/3", "a/4"], next: "TOKEN2" },
      { keys: ["a/5"] },
    ])
    const keys = await store.listKeys("a/")
    expect(keys).toEqual(["a/1", "a/2", "a/3", "a/4", "a/5"])
    expect(calls).toHaveLength(3)
    expect(calls[0]!.ContinuationToken).toBeUndefined()
    expect(calls[1]!.ContinuationToken).toBe("TOKEN1")
    expect(calls[2]!.ContinuationToken).toBe("TOKEN2")
  })

  it("stops early once an explicit limit is satisfied", async () => {
    const { store, calls } = makeStore([
      { keys: ["a/1", "a/2", "a/3"], next: "TOKEN1" },
      { keys: ["a/4"] },
    ])
    const keys = await store.listKeys("a/", { limit: 2 })
    expect(keys).toEqual(["a/1", "a/2"])
    expect(calls).toHaveLength(1) // did not fetch the second page
  })

  it("sends StartAfter only on the first page, then the continuation token", async () => {
    const { store, calls } = makeStore([
      { keys: ["a/2"], next: "TOKEN1" },
      { keys: ["a/3"] },
    ])
    await store.listKeys("a/", { startAfter: "a/1" })
    expect(calls[0]!.StartAfter).toBe("a/1")
    expect(calls[1]!.StartAfter).toBeUndefined()
    expect(calls[1]!.ContinuationToken).toBe("TOKEN1")
  })
})
