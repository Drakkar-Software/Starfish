/**
 * secp256k1 KEM keyring tests: cross-language vector conformance, the four
 * tolerant-reader tag combinations (kemAlg/addedByAlg present×absent), and
 * downgrade + fail-closed canaries.
 */

import { describe, it, expect, beforeAll } from "vitest"
import { configurePlatform, getSuite } from "@drakkar.software/starfish-protocol"
import { ed25519 } from "@noble/curves/ed25519.js"
import {
  wrapForRecipient,
  unwrapFromEntry,
  verifyEntrySignature,
  createKeyring,
  createKeyringEncryptor,
  rotateEpoch,
  type WrappedKeyEntry,
} from "../src/keyring.js"
import vec from "../../../../tests/test-vectors/keyring-wrap-secp256k1.json"

beforeAll(() => {
  if (typeof globalThis.btoa !== "function") {
    configurePlatform({
      base64: {
        encode: (d) => Buffer.from(d).toString("base64"),
        decode: (s) => new Uint8Array(Buffer.from(s, "base64")),
      },
    })
  }
})

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

const cek = hexToBytes(vec.cek)
const secp = getSuite("secp256k1-schnorr")
const edKem = getSuite("ed25519")

/** A secp256k1 sign+KEM keypair (one key does both). */
function secpKeypair() {
  return secp.generateKemKeypair()
}
/** An Ed25519 signing keypair (hex). */
function edSignKeypair() {
  const priv = ed25519.utils.randomSecretKey()
  return { privHex: Buffer.from(priv).toString("hex"), pubHex: Buffer.from(ed25519.getPublicKey(priv)).toString("hex") }
}

describe("secp256k1 keyring wrap — cross-language vector", () => {
  for (const c of vec.cases) {
    it(`reproduces "${c.label}" byte-for-byte, verifies, and unwraps`, async () => {
      const entry = await wrapForRecipient(cek, c.recipientKemPubHex, {
        adderEdPrivHex: c.adderPrivHex,
        adderEdPubHex: c.adderPubHex,
        addedAt: c.addedAt,
        epoch: c.epoch,
        kemAlg: c.kemAlg as "secp256k1-schnorr",
        addedByAlg: c.addedByAlg as "ed25519" | "secp256k1-schnorr",
        ephPriv: hexToBytes(c.ephPrivHex),
        iv: hexToBytes(c.ivHex),
      })
      expect(entry).toEqual(c.entry) // byte-identical to coincurve
      expect(await verifyEntrySignature(entry as WrappedKeyEntry, c.epoch)).toBe(true)
      const got = await unwrapFromEntry(entry as WrappedKeyEntry, c.recipientKemPrivHex)
      expect(Buffer.from(got).toString("hex")).toBe(vec.cek)
    })
  }
})

// Cross-language downgrade canaries: shared negative vectors that tamper with a
// signed secp256k1 entry (strip/swap the kemAlg/addedByAlg tags). Both TS and
// Python feed each straight into verify and MUST reject it — proving the guard
// cross-language, not just per-implementation (mirrors Python).
describe("secp256k1 keyring wrap — negative cross-language vectors", () => {
  for (const n of vec.negativeCases) {
    it(`rejects "${n.label}"`, async () => {
      expect(n.expectVerify).toBe(false)
      expect(await verifyEntrySignature(n.entry as unknown as WrappedKeyEntry, n.epoch)).toBe(false)
    })
  }
})

// The four tolerant-reader combinations of (kemAlg present?) × (addedByAlg
// present?). "absent" means the ed25519 default (omitted on the wire); the
// canonical addedSig input must include each tag only when present.
describe("secp256k1 keyring wrap — tag matrix + roundtrip (both directions)", () => {
  it("both absent: ed25519 adder + ed25519/X25519 recipient (no tags)", async () => {
    const adder = edSignKeypair()
    const r = edKem.generateKemKeypair()
    const entry = await wrapForRecipient(cek, r.pubHex, {
      adderEdPrivHex: adder.privHex,
      adderEdPubHex: adder.pubHex,
      addedAt: 1,
      epoch: 1,
    })
    expect(entry.kemAlg).toBeUndefined()
    expect(entry.addedByAlg).toBeUndefined()
    expect(await verifyEntrySignature(entry, 1)).toBe(true)
    expect(Buffer.from(await unwrapFromEntry(entry, r.privHex)).toString("hex")).toBe(vec.cek)
  })

  it("kemAlg only: ed25519 adder seals to a secp256k1 member", async () => {
    const adder = edSignKeypair()
    const r = secpKeypair()
    const entry = await wrapForRecipient(cek, r.pubHex, {
      adderEdPrivHex: adder.privHex,
      adderEdPubHex: adder.pubHex,
      addedAt: 1,
      epoch: 1,
      kemAlg: "secp256k1-schnorr",
    })
    expect(entry.kemAlg).toBe("secp256k1-schnorr")
    expect(entry.addedByAlg).toBeUndefined()
    expect(await verifyEntrySignature(entry, 1)).toBe(true)
    expect(Buffer.from(await unwrapFromEntry(entry, r.privHex)).toString("hex")).toBe(vec.cek)
  })

  it("addedByAlg only: secp256k1 owner seals to an ed25519/X25519 member", async () => {
    const adder = secpKeypair()
    const r = edKem.generateKemKeypair()
    const entry = await wrapForRecipient(cek, r.pubHex, {
      adderEdPrivHex: adder.privHex,
      adderEdPubHex: adder.pubHex,
      addedAt: 1,
      epoch: 1,
      addedByAlg: "secp256k1-schnorr",
    })
    expect(entry.kemAlg).toBeUndefined()
    expect(entry.addedByAlg).toBe("secp256k1-schnorr")
    expect(await verifyEntrySignature(entry, 1)).toBe(true)
    expect(Buffer.from(await unwrapFromEntry(entry, r.privHex)).toString("hex")).toBe(vec.cek)
  })

  it("both present: secp256k1 owner seals to a secp256k1 member", async () => {
    const adder = secpKeypair()
    const r = secpKeypair()
    const entry = await wrapForRecipient(cek, r.pubHex, {
      adderEdPrivHex: adder.privHex,
      adderEdPubHex: adder.pubHex,
      addedAt: 1,
      epoch: 1,
      kemAlg: "secp256k1-schnorr",
      addedByAlg: "secp256k1-schnorr",
    })
    expect(entry.kemAlg).toBe("secp256k1-schnorr")
    expect(entry.addedByAlg).toBe("secp256k1-schnorr")
    expect(await verifyEntrySignature(entry, 1)).toBe(true)
    expect(Buffer.from(await unwrapFromEntry(entry, r.privHex)).toString("hex")).toBe(vec.cek)
  })
})

describe("secp256k1 keyring lifecycle — owner seals, member decrypts (end-to-end)", () => {
  it("secp256k1 owner creates a keyring sealed to a secp256k1 member; member decrypts", async () => {
    const owner = secpKeypair()
    const member = secpKeypair()
    const { keyring } = await createKeyring(
      { edPrivHex: owner.privHex, edPubHex: owner.pubHex, alg: "secp256k1-schnorr" },
      [{ subKemHex: member.pubHex, kemAlg: "secp256k1-schnorr" }],
    )
    const enc = await createKeyringEncryptor(
      keyring,
      { kemPubHex: member.pubHex, kemPrivHex: member.privHex },
      { trustedAdders: [owner.pubHex] },
    )
    const sealed = await enc.encrypt({ hello: "nostr" })
    expect(await enc.decrypt(sealed)).toEqual({ hello: "nostr" })
  })

  it("ed25519 owner seals a keyring to a secp256k1 member; member decrypts (mixed)", async () => {
    const owner = edSignKeypair()
    const member = secpKeypair()
    const { keyring } = await createKeyring(
      { edPrivHex: owner.privHex, edPubHex: owner.pubHex }, // ed25519 adder (default)
      [{ subKemHex: member.pubHex, kemAlg: "secp256k1-schnorr" }],
    )
    const enc = await createKeyringEncryptor(
      keyring,
      { kemPubHex: member.pubHex, kemPrivHex: member.privHex },
      { trustedAdders: [owner.pubHex] },
    )
    const sealed = await enc.encrypt({ x: 1 })
    expect(await enc.decrypt(sealed)).toEqual({ x: 1 })
  })

  it("rotateEpoch retains a secp256k1 member, who decrypts the new epoch", async () => {
    const owner = secpKeypair()
    const member = secpKeypair()
    const { keyring } = await createKeyring(
      { edPrivHex: owner.privHex, edPubHex: owner.pubHex, alg: "secp256k1-schnorr" },
      [{ subKemHex: member.pubHex, kemAlg: "secp256k1-schnorr" }],
    )
    const { keyring: rotated } = await rotateEpoch(
      keyring,
      { edPrivHex: owner.privHex, edPubHex: owner.pubHex, alg: "secp256k1-schnorr" },
      [{ subKemHex: member.pubHex, kemAlg: "secp256k1-schnorr" }],
    )
    expect(rotated.currentEpoch).toBe(2)
    const enc = await createKeyringEncryptor(
      rotated,
      { kemPubHex: member.pubHex, kemPrivHex: member.privHex },
      { trustedAdders: [owner.pubHex] },
    )
    const sealed = await enc.encrypt({ epoch: 2 })
    expect(await enc.decrypt(sealed)).toEqual({ epoch: 2 })
  })

  it("rotateEpoch drops a secp256k1 member: the removed key cannot recover the new epoch's CEK", async () => {
    // Cryptographic revocation proof (not just structural): the dropped member
    // keeps their stale epoch-1 entry, but currentEpoch is 2 and they have no
    // epoch-2 entry, so they can never obtain the new CEK.
    const owner = secpKeypair()
    const kept = secpKeypair()
    const dropped = secpKeypair()
    const { keyring } = await createKeyring(
      { edPrivHex: owner.privHex, edPubHex: owner.pubHex, alg: "secp256k1-schnorr" },
      [
        { subKemHex: kept.pubHex, kemAlg: "secp256k1-schnorr" },
        { subKemHex: dropped.pubHex, kemAlg: "secp256k1-schnorr" },
      ],
    )
    // Re-wrap retaining only `kept`; `dropped` is excluded from the new epoch.
    const { keyring: rotated } = await rotateEpoch(
      keyring,
      { edPrivHex: owner.privHex, edPubHex: owner.pubHex, alg: "secp256k1-schnorr" },
      [{ subKemHex: kept.pubHex, kemAlg: "secp256k1-schnorr" }],
    )
    expect(rotated.currentEpoch).toBe(2)
    // Retained member still decrypts the new epoch.
    const keptEnc = await createKeyringEncryptor(
      rotated,
      { kemPubHex: kept.pubHex, kemPrivHex: kept.privHex },
      { trustedAdders: [owner.pubHex] },
    )
    expect(await keptEnc.decrypt(await keptEnc.encrypt({ ok: 1 }))).toEqual({ ok: 1 })
    // Dropped member: no entry in epoch 2 → encryptor construction fails closed.
    await expect(
      createKeyringEncryptor(
        rotated,
        { kemPubHex: dropped.pubHex, kemPrivHex: dropped.privHex },
        { trustedAdders: [owner.pubHex] },
      ),
    ).rejects.toThrow(/current epoch 2/)
  })
})

describe("secp256k1 keyring wrap — downgrade + fail-closed canaries", () => {
  async function bothTagsEntry(): Promise<WrappedKeyEntry> {
    const adder = secpKeypair()
    const r = secpKeypair()
    const entry = await wrapForRecipient(cek, r.pubHex, {
      adderEdPrivHex: adder.privHex,
      adderEdPubHex: adder.pubHex,
      addedAt: 1,
      epoch: 1,
      kemAlg: "secp256k1-schnorr",
      addedByAlg: "secp256k1-schnorr",
    })
    return entry
  }

  it("stripping kemAlg fails verification (downgrade caught)", async () => {
    const entry = await bothTagsEntry()
    expect(await verifyEntrySignature({ ...entry, kemAlg: undefined }, 1)).toBe(false)
  })

  it("stripping addedByAlg fails verification (downgrade caught)", async () => {
    const entry = await bothTagsEntry()
    expect(await verifyEntrySignature({ ...entry, addedByAlg: undefined }, 1)).toBe(false)
  })

  it("swapping addedByAlg to ed25519 fails verification", async () => {
    const entry = await bothTagsEntry()
    // Verify would dispatch ed25519 over a secp256k1 signature → false, and the
    // canonical input no longer matches the signed bytes anyway.
    expect(await verifyEntrySignature({ ...entry, addedByAlg: "ed25519" }, 1)).toBe(false)
  })

  it("unwrap fails closed on a malformed (off-curve) ephKem", async () => {
    const entry = await bothTagsEntry()
    const r = secpKeypair()
    // 0xFF…FF is not a valid x-coordinate → deriveSharedSecret throws → unwrap rejects.
    await expect(
      unwrapFromEntry({ ...entry, ephKem: "ff".repeat(32) }, r.privHex),
    ).rejects.toThrow()
  })

  it("verifyEntrySignature returns false (never throws) on a junk signature", async () => {
    const entry = await bothTagsEntry()
    expect(await verifyEntrySignature({ ...entry, addedSig: "!!notbase64!!" }, 1)).toBe(false)
  })

  it("verifyEntrySignature returns false (never throws) on an unknown addedByAlg", async () => {
    // A tampered entry naming an unimplemented suite must fail closed, not throw
    // out of recoverCurrentCek/listRecipients (a server-injected-entry DoS).
    const entry = await bothTagsEntry()
    expect(await verifyEntrySignature({ ...entry, addedByAlg: "rsa" as never }, 1)).toBe(false)
  })

  it("verifyEntrySignature returns false on an empty-string addedByAlg (parity with Python)", async () => {
    // `""` is server-controlled and unvalidated at parse; only None defaults, so
    // an empty tag fails closed identically in both languages (no verify fork).
    const entry = await bothTagsEntry()
    expect(await verifyEntrySignature({ ...entry, addedByAlg: "" as never }, 1)).toBe(false)
  })
})
