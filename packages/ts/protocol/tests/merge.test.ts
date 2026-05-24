import { describe, it, expect, afterEach } from "vitest"
import { deepMerge } from "../src/merge.js"

describe("deepMerge", () => {
  it("performs a remote-wins merge for plain values", () => {
    const out = deepMerge({ a: 1, b: 2 }, { b: 3, c: 4 })
    expect(out).toEqual({ a: 1, b: 3, c: 4 })
  })

  it("recurses into nested objects but lets remote primitives win", () => {
    const out = deepMerge(
      { meta: { count: 1, label: "old" } },
      { meta: { label: "new" } },
    )
    expect(out).toEqual({ meta: { count: 1, label: "new" } })
  })

  // --- prototype pollution surface ---

  afterEach(() => {
    // Defensive: even if a test pollutes Object.prototype, clean up so other
    // suites in the same vitest worker aren't poisoned.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    delete (Object.prototype as any).isAdmin
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    delete (Object.prototype as any).polluted
  })

  it("does NOT pollute Object.prototype when remote contains __proto__", () => {
    const remote = JSON.parse('{"__proto__":{"isAdmin":true}}') as Record<string, unknown>
    deepMerge({}, remote)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(({} as any).isAdmin).toBeUndefined()
  })

  it("drops __proto__/constructor/prototype keys from the result entirely", () => {
    // Even though the bracket-notation assignment doesn't pollute
    // Object.prototype in V8, the merged result must not carry these keys
    // (they could re-trigger pollution if the caller re-serialises and a
    // downstream consumer assigns them with dot syntax).
    const remote = JSON.parse(
      '{"__proto__":{"isAdmin":true},"constructor":{"prototype":{"polluted":true}},"prototype":{"polluted":true}}',
    ) as Record<string, unknown>
    const result = deepMerge({ keep: 1 }, remote)
    expect(Object.prototype.hasOwnProperty.call(result, "__proto__")).toBe(false)
    expect(Object.prototype.hasOwnProperty.call(result, "constructor")).toBe(false)
    expect(Object.prototype.hasOwnProperty.call(result, "prototype")).toBe(false)
    expect(Object.getPrototypeOf(result)).toBe(Object.prototype)
    // Sanity: legitimate keys are preserved.
    expect(result["keep"]).toBe(1)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(({} as any).polluted).toBeUndefined()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(({} as any).isAdmin).toBeUndefined()
  })

  it("nested __proto__ inside a sub-object is also dropped", () => {
    const remote = JSON.parse('{"meta":{"__proto__":{"isAdmin":true}}}') as Record<string, unknown>
    const out = deepMerge({ meta: { ok: 1 } }, remote)
    const meta = out["meta"] as Record<string, unknown>
    expect(Object.prototype.hasOwnProperty.call(meta, "__proto__")).toBe(false)
    expect(Object.getPrototypeOf(meta)).toBe(Object.prototype)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(({} as any).isAdmin).toBeUndefined()
  })

  it("drops the Python dunder vectors __class__ / __dict__ too (cross-language parity)", () => {
    const remote = JSON.parse('{"__class__":"x","__dict__":"y","ok":2}') as Record<string, unknown>
    const out = deepMerge({ keep: 1 }, remote)
    expect(Object.prototype.hasOwnProperty.call(out, "__class__")).toBe(false)
    expect(Object.prototype.hasOwnProperty.call(out, "__dict__")).toBe(false)
    expect(out).toEqual({ keep: 1, ok: 2 })
  })

  it("drops an unsafe key already present in the LOCAL side (not just remote)", () => {
    const local = JSON.parse('{"keep":1,"constructor":"bad","__class__":"bad"}') as Record<string, unknown>
    const out = deepMerge(local, { ok: 2 })
    expect(Object.prototype.hasOwnProperty.call(out, "constructor")).toBe(false)
    expect(Object.prototype.hasOwnProperty.call(out, "__class__")).toBe(false)
    expect(out).toEqual({ keep: 1, ok: 2 })
  })

  // --- type transitions (remote always wins for non-object/object pairs) ---

  it("lets a remote scalar replace a local object wholesale", () => {
    expect(deepMerge({ a: { x: 1 } }, { a: 5 })).toEqual({ a: 5 })
  })

  it("lets a remote object replace a local scalar wholesale", () => {
    expect(deepMerge({ a: 5 }, { a: { x: 1 } })).toEqual({ a: { x: 1 } })
  })

  it("replaces a local array with the remote array wholesale (no element merge)", () => {
    expect(deepMerge({ a: [1, 2, 3] }, { a: [9] })).toEqual({ a: [9] })
  })

  it("lets a remote null overwrite a local object (null is not a mergeable object)", () => {
    // remoteVal === null fails the recursion guard, so the remote-wins branch
    // assigns null verbatim. Matches Python's deep_merge (None is not a dict).
    expect(deepMerge({ a: { x: 1 }, b: 2 }, { a: null })).toEqual({ a: null, b: 2 })
  })

  it("lets a remote object replace a local null", () => {
    // localVal === null fails the recursion guard, so the remote object wins
    // wholesale rather than merging into the null. Matches Python's deep_merge.
    expect(deepMerge({ a: null }, { a: { x: 1 } })).toEqual({ a: { x: 1 } })
  })

  it("copies array-nested objects verbatim — the dunder scrub does not enter arrays", () => {
    // The scrub walks object values at every depth, but an array is taken
    // whole by the remote-wins branch, so a dunder key inside an array element
    // rides along. Matches the Python deep_merge; pinned so the boundary can't
    // drift in one language only. (The document root is still scrubbed below.)
    const remote = JSON.parse('{"items":[{"__proto__":1,"ok":2}]}') as Record<string, unknown>
    const out = deepMerge({}, remote)
    const el = (out["items"] as Record<string, unknown>[])[0]
    expect(Object.prototype.hasOwnProperty.call(el, "__proto__")).toBe(true)
    expect(el["ok"]).toBe(2)
  })

  it("drops a top-level dunder while an array-nested one survives", () => {
    const remote = JSON.parse('{"__proto__":9,"items":[{"__proto__":1}]}') as Record<string, unknown>
    const out = deepMerge({}, remote)
    expect(Object.prototype.hasOwnProperty.call(out, "__proto__")).toBe(false)
    const el = (out["items"] as Record<string, unknown>[])[0]
    expect(Object.prototype.hasOwnProperty.call(el, "__proto__")).toBe(true)
  })
})
