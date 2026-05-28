import { describe, it, expect } from "vitest"
import * as ed25519Suite from "../src/suites/ed25519.js"
import { assertUsableSharedSecret, hexToBytes as decodeHex } from "../src/suites/_hex.js"

describe("ed25519 suite primitives", () => {
  const priv = "ad5a91be445615ad20823ff607df3d69f9fabc7a2f3f6cfce79dd6b8827e1a89"
  const message = new TextEncoder().encode("hello starfish")

  it("sign then verify round-trips", async () => {
    const { ed25519 } = await import("@noble/curves/ed25519.js")
    const pubBytes = ed25519.getPublicKey(decodeHex(priv))
    const pub = Array.from(pubBytes, (b) => b.toString(16).padStart(2, "0")).join("")
    const sig = ed25519Suite.sign(message, priv)
    expect(ed25519Suite.verify(sig, message, pub)).toBe(true)
  })

  it("verify fails closed on malformed inputs (never throws)", () => {
    const m = new TextEncoder().encode("m")
    expect(ed25519Suite.verify(new Uint8Array(64), m, "abc")).toBe(false) // odd-length hex
    expect(ed25519Suite.verify(new Uint8Array(64), m, "ab")).toBe(false) // wrong-length pubkey
    expect(ed25519Suite.verify(new Uint8Array(64), m, "")).toBe(false) // empty pubkey
    expect(ed25519Suite.verify(new Uint8Array(3), m, "aa".repeat(32))).toBe(false) // wrong-length sig
  })

  it("X25519 ECDH: symmetric and rejects a low-order peer", () => {
    const a = ed25519Suite.generateKemKeypair()
    const b = ed25519Suite.generateKemKeypair()
    const ab = ed25519Suite.deriveSharedSecret(a.privHex, b.pubHex)
    const ba = ed25519Suite.deriveSharedSecret(b.privHex, a.pubHex)
    expect([...ab]).toEqual([...ba])
    expect(() => ed25519Suite.deriveSharedSecret(a.privHex, "00".repeat(32))).toThrow()
  })
})

describe("assertUsableSharedSecret — the degenerate-point backstop", () => {
  it("throws on an all-zero shared secret", () => {
    expect(() => assertUsableSharedSecret(new Uint8Array(32))).toThrow(/zero KEM shared secret/)
  })

  it("accepts a non-zero shared secret (one non-zero byte is enough)", () => {
    const s = new Uint8Array(32)
    s[31] = 1
    expect(() => assertUsableSharedSecret(s)).not.toThrow()
  })
})

describe("hexToBytes input validation", () => {
  it("decodes valid lowercase and uppercase hex", () => {
    expect([...decodeHex("00ff")]).toEqual([0, 255])
    expect([...decodeHex("DEadBE")]).toEqual([0xde, 0xad, 0xbe])
    expect([...decodeHex("")]).toEqual([])
  })

  it("throws on non-hex characters instead of silently zeroing (fail-closed, matches Python)", () => {
    // Before the fix `parseInt("zz",16)` → NaN → 0, so malformed hex became
    // zero bytes silently (and diverged from Python's `bytes.fromhex`).
    expect(() => decodeHex("zz")).toThrow(/invalid characters/)
    expect(() => decodeHex("0g")).toThrow(/invalid characters/)
    expect(() => decodeHex("0xff")).toThrow(/invalid characters/)
    expect(() => decodeHex("12cz")).toThrow(/invalid characters/)
  })

  it("throws on an odd-length string", () => {
    expect(() => decodeHex("abc")).toThrow(/odd length/)
  })
})
