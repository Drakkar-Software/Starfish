/**
 * Tests for the pure-JS base64 fallback codec (active on React Native / Hermes,
 * where btoa/atob are absent). Focuses on strict rejection of non-alphabet input
 * so TS and Python agree on which cap-cert nonces/signatures are well-formed.
 */
import { describe, it, expect } from "vitest"
import { getBase64 } from "../src/platform.js"

function withPureCodec<T>(fn: (decode: (s: string) => Uint8Array) => T): T {
  const g = globalThis as unknown as { btoa?: unknown; atob?: unknown }
  const savedBtoa = g.btoa
  const savedAtob = g.atob
  // Force the pure-JS fallback path (getBase64 returns it only when btoa/atob
  // are unavailable, as on RN/Hermes).
  g.btoa = undefined
  g.atob = undefined
  try {
    return fn(getBase64().decode)
  } finally {
    g.btoa = savedBtoa
    g.atob = savedAtob
  }
}

describe("pure base64 codec (RN/Hermes fallback)", () => {
  it("round-trips valid standard base64", () => {
    withPureCodec((decode) => {
      expect(Array.from(decode("YWJj"))).toEqual([0x61, 0x62, 0x63]) // "abc"
    })
  })

  it("rejects characters outside the alphabet (strict, matches Python validate=True)", () => {
    withPureCodec((decode) => {
      // The old lenient decoder silently skipped these bytes, so a Hermes/RN TS
      // node accepted malformed base64 that a Python node rejected.
      expect(() => decode("YW Jj")).toThrow(/invalid base64/)
      expect(() => decode("YWJj!!")).toThrow(/invalid base64/)
      expect(() => decode("YW\nJj")).toThrow(/invalid base64/)
    })
  })
})
