/**
 * Tests for the platform Base64 provider — verifies the chunked encoder
 * handles arbitrary sizes correctly, including multi-megabyte blobs that
 * would overflow the call-stack with the old spread-based implementation.
 */
import { describe, it, expect } from "vitest"
import { getBase64 } from "../src/platform.js"

function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n)
  // Fill with a deterministic pattern so tests are reproducible.
  for (let i = 0; i < n; i++) buf[i] = i % 256
  return buf
}

describe("getBase64 — chunked provider", () => {
  it("round-trips a small payload (< one chunk)", () => {
    const b64 = getBase64()
    const data = new Uint8Array([0, 1, 127, 128, 255])
    expect(b64.decode(b64.encode(data))).toEqual(data)
  })

  it("round-trips exactly 3 bytes (no padding)", () => {
    const b64 = getBase64()
    const data = new Uint8Array([0xde, 0xad, 0xbe])
    const encoded = b64.encode(data)
    expect(encoded.endsWith("=")).toBe(false)
    expect(b64.decode(encoded)).toEqual(data)
  })

  it("round-trips 1-mod-3 length (two padding chars)", () => {
    const b64 = getBase64()
    const data = new Uint8Array([0xca, 0xfe, 0xba, 0xbe, 0x01])
    expect(b64.decode(b64.encode(data))).toEqual(data)
  })

  it("round-trips 2-mod-3 length (one padding char)", () => {
    const b64 = getBase64()
    const data = new Uint8Array([0x01, 0x02, 0x03, 0x04])
    expect(b64.decode(b64.encode(data))).toEqual(data)
  })

  it("round-trips an empty payload", () => {
    const b64 = getBase64()
    const data = new Uint8Array(0)
    expect(b64.decode(b64.encode(data))).toEqual(data)
  })

  it("round-trips exactly one chunk boundary (24 576 bytes)", () => {
    const b64 = getBase64()
    const data = randomBytes(0x6000)
    expect(b64.decode(b64.encode(data))).toEqual(data)
  })

  it("round-trips a multi-megabyte blob without stack overflow (was the original bug)", () => {
    const b64 = getBase64()
    // 8 MB — the old `btoa(String.fromCharCode(...data))` spread would throw here.
    const data = randomBytes(8 * 1024 * 1024)
    const encoded = b64.encode(data)
    expect(typeof encoded).toBe("string")
    expect(encoded.length).toBeGreaterThan(0)
    const decoded = b64.decode(encoded)
    expect(decoded.byteLength).toBe(data.byteLength)
    // Spot-check first and last bytes instead of comparing the full 8 MB.
    expect(decoded[0]).toBe(data[0])
    expect(decoded[data.byteLength - 1]).toBe(data[data.byteLength - 1])
  })

  it("encodes to the same string as btoa for small payloads", () => {
    const b64 = getBase64()
    const data = new Uint8Array([104, 101, 108, 108, 111]) // "hello"
    expect(b64.encode(data)).toBe(btoa("hello"))
  })
})
