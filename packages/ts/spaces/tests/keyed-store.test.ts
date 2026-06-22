/**
 * Tests for `KeyedStore` and `createComposedStore`.
 */
import { describe, it, expect } from "vitest"
import { createKeyedStore, createComposedStore } from "../src/keyed-store.js"

describe("createKeyedStore", () => {
  it("stores and retrieves values", () => {
    const store = createKeyedStore<number>()
    store.set("a", 1)
    expect(store.get("a")).toBe(1)
  })

  it("returns undefined for missing keys", () => {
    const store = createKeyedStore<string>()
    expect(store.get("missing")).toBeUndefined()
  })

  it("clears a specific key", () => {
    const store = createKeyedStore<string>()
    store.set("x", "hello")
    store.clear("x")
    expect(store.get("x")).toBeUndefined()
  })

  it("round-trips via serialize/hydrate", () => {
    const store = createKeyedStore<number>()
    store.set("a", 42)
    store.set("b", 99)
    const json = store.serialize()
    const store2 = createKeyedStore<number>()
    store2.hydrate(json)
    expect(store2.get("a")).toBe(42)
    expect(store2.get("b")).toBe(99)
  })
})

describe("createComposedStore", () => {
  it("provides scoped get/set/clear by composed key", () => {
    const { for: forKey } = createComposedStore<string, [string, string]>(
      (a, b) => `${a}:${b}`,
    )
    forKey("sp-1", "obj-1").set("hello")
    expect(forKey("sp-1", "obj-1").get()).toBe("hello")
    expect(forKey("sp-1", "obj-2").get()).toBeUndefined()
  })

  it("clear removes the entry", () => {
    const { for: forKey } = createComposedStore<number, [string]>((k) => k)
    forKey("x").set(5)
    forKey("x").clear()
    expect(forKey("x").get()).toBeUndefined()
  })
})
