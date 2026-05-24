import { describe, it, expect, vi, beforeEach } from "vitest"
import { ARGON2_PARAMS } from "../src/identity.js"

// Replace the Argon2id KDF with a spy so we can prove the open-side validation
// rejects hostile envelopes BEFORE any (potentially multi-GiB) KDF work runs.
const { argon2idSpy } = vi.hoisted(() => ({
  argon2idSpy: vi.fn(async () => new Uint8Array(32)),
}))
vi.mock("hash-wasm", () => ({ argon2id: argon2idSpy }))

import { openWithPassphrase, type SealedEnvelope } from "../src/seal.js"

const SALT_B64 = "AAAAAAAAAAAAAAAAAAAAAA==" // 16 zero bytes
const IV_B64 = "AAAAAAAAAAAAAAAA" // 12 zero bytes
const CT_B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" // arbitrary

function envelopeWith(overrides: Partial<SealedEnvelope["kdf"]> & { enc?: string }): SealedEnvelope {
  const { enc, ...kdfOverrides } = overrides
  return {
    v: 1,
    enc: (enc ?? "passphrase") as "passphrase",
    kdf: {
      alg: "argon2id",
      memKiB: ARGON2_PARAMS.memoryKiB,
      iter: ARGON2_PARAMS.iterations,
      par: ARGON2_PARAMS.parallelism,
      salt: SALT_B64,
      ...kdfOverrides,
    },
    iv: IV_B64,
    ct: CT_B64,
  }
}

describe("openWithPassphrase — rejects hostile envelopes before invoking Argon2id", () => {
  beforeEach(() => argon2idSpy.mockClear())

  it("rejects an inflated KDF memory cost (DoS guard) without running the KDF", async () => {
    await expect(openWithPassphrase("pw", envelopeWith({ memKiB: 4_000_000 }))).rejects.toThrow()
    expect(argon2idSpy).not.toHaveBeenCalled()
  })

  it("rejects an inflated KDF iteration count (time-cost DoS) without running the KDF", async () => {
    await expect(openWithPassphrase("pw", envelopeWith({ iter: 10_000_000 }))).rejects.toThrow()
    expect(argon2idSpy).not.toHaveBeenCalled()
  })

  it("rejects an inflated KDF parallelism without running the KDF", async () => {
    await expect(openWithPassphrase("pw", envelopeWith({ par: 255 }))).rejects.toThrow()
    expect(argon2idSpy).not.toHaveBeenCalled()
  })

  it("rejects an unknown KDF algorithm without running the KDF", async () => {
    await expect(openWithPassphrase("pw", envelopeWith({ alg: "scrypt" as "argon2id" }))).rejects.toThrow()
    expect(argon2idSpy).not.toHaveBeenCalled()
  })

  it("rejects an unknown enc discriminator without running the KDF", async () => {
    await expect(openWithPassphrase("pw", envelopeWith({ enc: "rot13" }))).rejects.toThrow()
    expect(argon2idSpy).not.toHaveBeenCalled()
  })

  it("rejects a wrong-length salt without running the KDF", async () => {
    await expect(openWithPassphrase("pw", envelopeWith({ salt: "AAAA" }))).rejects.toThrow()
    expect(argon2idSpy).not.toHaveBeenCalled()
  })
})
