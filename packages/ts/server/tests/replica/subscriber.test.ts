import { describe, it, expect } from "vitest"
import { SubscriptionStore } from "../../src/replica/subscriber.js"
import { createIsolatedStore } from "../helpers.js"

describe("SubscriptionStore", () => {
  it("adds and lists subscriptions", async () => {
    const store = new SubscriptionStore(createIsolatedStore())
    await store.add("https://replica.example.com/notify", ["col1", "col2"], 1000)
    const subs = await store.listAll()
    expect(subs).toHaveLength(1)
    expect(subs[0].webhookUrl).toBe("https://replica.example.com/notify")
    expect(subs[0].collections).toEqual(["col1", "col2"])
  })

  it("filters by collection", async () => {
    const store = new SubscriptionStore(createIsolatedStore())
    await store.add("https://a.com/notify", ["col1"], 1000)
    await store.add("https://b.com/notify", ["col2"], 1000)
    await store.add("https://c.com/notify", ["col1", "col2"], 1000)

    const col1Subs = await store.listForCollection("col1")
    expect(col1Subs).toHaveLength(2)
    expect(col1Subs.map((s) => s.webhookUrl).sort()).toEqual([
      "https://a.com/notify",
      "https://c.com/notify",
    ])
  })

  it("replaces existing URL", async () => {
    const store = new SubscriptionStore(createIsolatedStore())
    await store.add("https://a.com/notify", ["col1"], 1000)
    await store.add("https://a.com/notify", ["col1", "col2"], 2000)
    const subs = await store.listAll()
    expect(subs).toHaveLength(1)
    expect(subs[0].collections).toEqual(["col1", "col2"])
    expect(subs[0].subscribedAt).toBe(2000)
  })

  it("removes subscription (idempotent)", async () => {
    const store = new SubscriptionStore(createIsolatedStore())
    await store.add("https://a.com/notify", ["col1"], 1000)
    await store.remove("https://a.com/notify")
    expect(await store.listAll()).toHaveLength(0)
    // idempotent
    await store.remove("https://a.com/notify")
    expect(await store.listAll()).toHaveLength(0)
  })

  it("persists across instances", async () => {
    const inner = createIsolatedStore()
    const store1 = new SubscriptionStore(inner)
    await store1.add("https://a.com/notify", ["col1"], 1000)

    const store2 = new SubscriptionStore(inner)
    const subs = await store2.listAll()
    expect(subs).toHaveLength(1)
  })
})
