import { describe, it, expect } from "vitest"
import {
  sealWithPassphrase,
  openWithPassphrase,
  isSealedEnvelope,
  type SealedEnvelope,
} from "../src/seal.js"
import vector from "../../../../tests/test-vectors/passphrase-seal.json"

const enc = new TextEncoder()
const dec = new TextDecoder()
const b64ToBytes = (s: string): Uint8Array => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
/** Flip the first base64 char to a different valid one — keeps the decoded length. */
const flip = (s: string): string => (s[0] === "A" ? "B" : "A") + s.slice(1)

interface SealVector {
  label: string
  passphrase: string
  plaintextUtf8: string
  saltB64: string
  ivB64: string
  envelope: SealedEnvelope
}
const VECTORS = (vector as { vectors: SealVector[] }).vectors

describe("sealWithPassphrase / openWithPassphrase — roundtrip", () => {
  it("opens to the exact plaintext with the correct passphrase", async () => {
    const pt = enc.encode("a secret setup code")
    const env = await sealWithPassphrase("hunter2", pt)
    const out = await openWithPassphrase("hunter2", env)
    expect(out).toEqual(pt)
  })

  it("rejects an empty passphrase at seal time", async () => {
    await expect(sealWithPassphrase("", enc.encode("x"))).rejects.toThrow()
  })

  it("produces a fresh random salt and iv each time", async () => {
    const a = await sealWithPassphrase("pw", enc.encode("same"))
    const b = await sealWithPassphrase("pw", enc.encode("same"))
    expect(a.kdf.salt).not.toBe(b.kdf.salt)
    expect(a.iv).not.toBe(b.iv)
    expect(a.ct).not.toBe(b.ct)
  })
})

describe("openWithPassphrase — failure parity (one generic error)", () => {
  it("wrong passphrase and tampered ciphertext throw the same message", async () => {
    const env = await sealWithPassphrase("right", enc.encode("payload"))

    const wrongPass = await openWithPassphrase("wrong", env).then(
      () => null,
      (e: Error) => e.message,
    )
    const tamperedCt = await openWithPassphrase("right", { ...env, ct: flip(env.ct) }).then(
      () => null,
      (e: Error) => e.message,
    )
    expect(wrongPass).toBeTruthy()
    expect(tamperedCt).toBe(wrongPass)
  })

  it("tampered salt and tampered iv both throw the same generic error", async () => {
    const env = await sealWithPassphrase("right", enc.encode("payload"))
    const re = /Failed to open sealed envelope/
    await expect(
      openWithPassphrase("right", { ...env, kdf: { ...env.kdf, salt: flip(env.kdf.salt) } }),
    ).rejects.toThrow(re)
    await expect(openWithPassphrase("right", { ...env, iv: flip(env.iv) })).rejects.toThrow(re)
  })
})

describe("NFC normalization", () => {
  it("a decomposed and a composed passphrase open the same envelope", async () => {
    // Build both forms from code points so the source stays pure-ASCII and the
    // composed/decomposed distinction can't be flattened by an editor.
    const composed = "caf" + String.fromCodePoint(0xe9) // café (U+00E9)
    const decomposed = "cafe" + String.fromCodePoint(0x301) // café (e + combining acute U+0301)
    expect(composed).not.toBe(decomposed)
    const env = await sealWithPassphrase(composed, enc.encode("unicode payload"))
    const out = await openWithPassphrase(decomposed, env)
    expect(dec.decode(out)).toBe("unicode payload")
  })
})

describe("isSealedEnvelope", () => {
  it("is true for a real envelope and false for a plaintext blob or junk", async () => {
    const env = await sealWithPassphrase("pw", enc.encode("x"))
    expect(isSealedEnvelope(env)).toBe(true)
    expect(isSealedEnvelope({ v: 1, keys: {}, bundle: {}, roomId: "general" })).toBe(false)
    expect(isSealedEnvelope(null)).toBe(false)
    expect(isSealedEnvelope("not an object")).toBe(false)
    expect(isSealedEnvelope({ v: 1, enc: "passphrase", iv: "x", ct: "y" })).toBe(false) // no kdf
  })
})

describe("passphrase-seal cross-language vectors", () => {
  for (const v of VECTORS) {
    it(`opens the ${v.label} vector to its plaintext`, async () => {
      const out = await openWithPassphrase(v.passphrase, v.envelope)
      expect(dec.decode(out)).toBe(v.plaintextUtf8)
    })

    it(`reproduces the ${v.label} envelope from (passphrase, plaintext, salt, iv)`, async () => {
      const env = await sealWithPassphrase(v.passphrase, enc.encode(v.plaintextUtf8), {
        salt: b64ToBytes(v.saltB64),
        iv: b64ToBytes(v.ivB64),
      })
      expect(env).toEqual(v.envelope)
    })
  }
})
