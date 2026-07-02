/**
 * Cross-instance append safety via compare-and-swap.
 *
 * appendItem's in-process writeChain serialises same-key writes within ONE
 * instance, but two server instances sharing one bucket both read-modify-write
 * the head with no coordination — the second silently drops the first's element.
 *
 * When the ObjectStore supports compare-and-swap (getWithEtag + putIfMatch),
 * appendItem writes the single-document head with an atomic CAS: on a detected
 * concurrent write it re-reads and retries rather than overwriting, and surfaces
 * an AppendConcurrencyError if the contention never clears.
 */
import { describe, it, expect } from "vitest"
import { appendItem, AppendConcurrencyError } from "../../src/protocol/push.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import type { ObjectStore, StoreContext } from "../../src/storage/base.js"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { webcrypto } from "node:crypto"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

/** A CAS-capable store that simulates a competing instance committing an
 *  element right before our putIfMatch runs. */
class CompetingWriterStore implements ObjectStore {
  private count = 0
  constructor(
    private readonly inner: MemoryObjectStore,
    private readonly key: string,
    /** When false, only the first putIfMatch is preceded by a competing write. */
    private readonly always: boolean,
  ) {}

  getString(key: string, ctx?: StoreContext) { return this.inner.getString(key, ctx) }
  put(key: string, body: string, opts?: { contentType?: string; cacheControl?: string }, ctx?: StoreContext) {
    return this.inner.put(key, body, opts, ctx)
  }
  listKeys(prefix: string, opts?: { startAfter?: string; limit?: number }, ctx?: StoreContext) {
    return this.inner.listKeys(prefix, opts, ctx)
  }
  delete(key: string, ctx?: StoreContext) { return this.inner.delete(key, ctx) }
  deleteMany(keys: string[], ctx?: StoreContext) { return this.inner.deleteMany(keys, ctx) }
  getWithEtag(key: string, ctx?: StoreContext) { return this.inner.getWithEtag(key, ctx) }

  async putIfMatch(
    key: string,
    body: string,
    expectedEtag: string | null,
    opts?: { contentType?: string; cacheControl?: string },
    ctx?: StoreContext,
  ): Promise<string | null> {
    if (key === this.key && (this.always || this.count === 0)) {
      this.count++
      // A concurrent instance commits a distinct element first, changing the
      // head etag so our CAS (built from the pre-read etag) must fail.
      const competitor = {
        v: 1,
        data: { items: [{ ts: this.count, data: { who: "other", n: this.count } }] },
        ts: this.count,
        hash: "competitor",
      }
      await this.inner.put(key, JSON.stringify(competitor))
    }
    return this.inner.putIfMatch(key, body, expectedEtag, opts, ctx)
  }
}

describe("appendItem cross-instance compare-and-swap", () => {
  it("retries and preserves the competing element instead of losing it", async () => {
    const inner = new MemoryObjectStore(new Map())
    const store = new CompetingWriterStore(inner, "col/doc", false)

    const out = await appendItem(store, "col/doc", { who: "me" }, "items", undefined)
    expect("error" in out).toBe(false)

    const raw = await inner.getString("col/doc")
    const doc = JSON.parse(raw!)
    // The competing element must survive AND our element is appended after it.
    expect(doc.data.items).toHaveLength(2)
    expect(doc.data.items[0].data).toEqual({ who: "other", n: 1 })
    expect(doc.data.items[1].data).toEqual({ who: "me" })
  })

  it("surfaces AppendConcurrencyError when contention never clears", async () => {
    const inner = new MemoryObjectStore(new Map())
    const store = new CompetingWriterStore(inner, "col/doc", true)

    await expect(
      appendItem(store, "col/doc", { who: "me" }, "items", undefined),
    ).rejects.toBeInstanceOf(AppendConcurrencyError)
  })

  it("stores without CAS keep last-write-wins (no throw, single element)", async () => {
    // A plain object store lacking getWithEtag/putIfMatch → fallback path.
    const data = new Map<string, string>()
    const inner = new MemoryObjectStore(data)
    const plain: ObjectStore = {
      getString: (k, c) => inner.getString(k, c),
      put: (k, b, o, c) => inner.put(k, b, o, c),
      listKeys: (p, o, c) => inner.listKeys(p, o, c),
      delete: (k, c) => inner.delete(k, c),
      deleteMany: (ks, c) => inner.deleteMany(ks, c),
    }
    const out = await appendItem(plain, "col/doc", { a: 1 }, "items", undefined)
    expect("error" in out).toBe(false)
    const doc = JSON.parse((await inner.getString("col/doc"))!)
    expect(doc.data.items).toHaveLength(1)
  })
})
