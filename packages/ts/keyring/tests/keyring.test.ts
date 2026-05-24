/**
 * Cross-language vector tests for v3.0 multi-recipient key wrapping.
 *
 * Reproduces the deterministic `wrappedKeys[0]` byte-for-byte using the
 * generator's `deterministic_eph_key(cek, recipientKemPub)` and the
 * `iv = HKDF(cek || recipientKemPub, salt="starfish-wrap-iv-vector", info="iv", length=12)`
 * derivation rules from `tests/test-vectors/_generators/multi_recipient_wrap.py`.
 */

import { describe, it, expect, beforeAll } from "vitest"
import { configurePlatform, getCrypto } from "@drakkar.software/starfish-protocol"
import { x25519 } from "@noble/curves/ed25519.js"
import {
  wrapForRecipient,
  unwrapFromEntry,
  verifyEntrySignature,
  createKeyring,
  addRecipient,
  rotateEpoch,
  createKeyringEncryptor,
  KEYRING_WRAP_SALT,
  KEYRING_WRAP_INFO,
  KEYRING_IV_BYTES,
  type Keyring,
  type WrappedKeyEntry,
} from "../src/keyring.js"
import vectors from "../../../../tests/test-vectors/multi-recipient-wrap.json"

beforeAll(() => {
  if (typeof globalThis.btoa !== "function") {
    configurePlatform({
      base64: {
        encode: (data) => Buffer.from(data).toString("base64"),
        decode: (str) => new Uint8Array(Buffer.from(str, "base64")),
      },
    })
  }
})

// ── Helpers ───────────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.byteLength, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.byteLength
  }
  return out
}

/**
 * HKDF-SHA256 → raw bytes. Mirrors the test vector generator's `hkdf(ikm, salt, info, length)`.
 */
async function hkdfBytes(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  lengthBytes: number,
): Promise<Uint8Array> {
  const subtle = getCrypto().subtle as unknown as SubtleCrypto
  const km = await subtle.importKey("raw", ikm as BufferSource, "HKDF", false, ["deriveBits"])
  const bits = await subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as BufferSource,
      info: info as BufferSource,
    },
    km,
    lengthBytes * 8,
  )
  return new Uint8Array(bits)
}

// Vector deterministic derivations (must match generator):
const EPH_SALT = new TextEncoder().encode("starfish-eph-test-vector")
const EPH_INFO = new TextEncoder().encode("x25519")
const IV_SALT = new TextEncoder().encode("starfish-wrap-iv-vector")
const IV_INFO = new TextEncoder().encode("iv")

async function deterministicEphKey(cek: Uint8Array, recipientKemPub: Uint8Array): Promise<Uint8Array> {
  return hkdfBytes(concat(cek, recipientKemPub), EPH_SALT, EPH_INFO, 32)
}

async function deterministicIv(cek: Uint8Array, recipientKemPub: Uint8Array): Promise<Uint8Array> {
  return hkdfBytes(concat(cek, recipientKemPub), IV_SALT, IV_INFO, 12)
}

// Typed access to vector.
interface VectorFixture {
  label: string
  passphrase: string
  edPriv: string
  edPub: string
  kemPriv: string
  kemPub: string
  userId: string
}
interface VectorShape {
  constants: {
    wrapSaltUtf8: string
    wrapInfoUtf8: string
    ivBytes: number
    addedSigCanonicalKeys: string[]
  }
  fixtures: Record<string, VectorFixture>
  cek: string
  keyring: {
    v: 1
    currentEpoch: number
    epochs: Record<
      string,
      { wrappedKeys: WrappedKeyEntry[]; createdAt: number }
    >
  }
  unwrapChecks: { recipient: string; expectedCek: string }[]
}
const V = vectors as unknown as VectorShape

// ── Constants ─────────────────────────────────────────────────────────────────

describe("keyring constants", () => {
  it("match the test vector locks", () => {
    expect(new TextDecoder().decode(KEYRING_WRAP_SALT)).toBe(V.constants.wrapSaltUtf8)
    expect(new TextDecoder().decode(KEYRING_WRAP_INFO)).toBe(V.constants.wrapInfoUtf8)
    expect(KEYRING_IV_BYTES).toBe(V.constants.ivBytes)
  })
})

// ── Deterministic wrap reproduction ───────────────────────────────────────────

describe("wrapForRecipient — deterministic vector reproduction", () => {
  it("reproduces wrappedKeys[0] byte-for-byte from the test vector", async () => {
    const cek = hexToBytes(V.cek)
    const recipient = V.fixtures.alice_dev_1
    const adder = V.fixtures.alice_root
    const expected = V.keyring.epochs["1"].wrappedKeys[0]

    const ephPriv = await deterministicEphKey(cek, hexToBytes(recipient.kemPub))
    const iv = await deterministicIv(cek, hexToBytes(recipient.kemPub))

    const entry = await wrapForRecipient(cek, recipient.kemPub, {
      adderEdPrivHex: adder.edPriv,
      adderEdPubHex: adder.edPub,
      addedAt: expected.addedAt,
      epoch: 1,
      ephPriv,
      iv,
    })

    expect(entry.subKem).toBe(expected.subKem)
    expect(entry.ephKem).toBe(expected.ephKem)
    expect(entry.ct).toBe(expected.ct)
    expect(entry.addedBy).toBe(expected.addedBy)
    expect(entry.addedAt).toBe(expected.addedAt)
    expect(entry.addedSig).toBe(expected.addedSig)
  })

  it("leaves a caller-supplied ephPriv intact and still unwraps (only a generated key is wiped)", async () => {
    const cek = hexToBytes(V.cek)
    const recipient = V.fixtures.alice_dev_1
    const adder = V.fixtures.alice_root
    const ephPriv = await deterministicEphKey(cek, hexToBytes(recipient.kemPub))
    const snapshot = Uint8Array.from(ephPriv)

    const entry = await wrapForRecipient(cek, recipient.kemPub, {
      adderEdPrivHex: adder.edPriv,
      adderEdPubHex: adder.edPub,
      addedAt: 99,
      epoch: 1,
      ephPriv,
    })
    // The wrap only zeroes a locally generated ephemeral key — the caller's
    // buffer must be untouched, and the entry must still unwrap to the CEK.
    expect(ephPriv).toEqual(snapshot)
    expect(ephPriv.some((b) => b !== 0)).toBe(true)
    const recovered = await unwrapFromEntry(entry, recipient.kemPriv)
    expect(recovered).toEqual(cek)
  })

  it("reproduces all three vector entries with deterministic ephPriv + iv", async () => {
    const cek = hexToBytes(V.cek)
    const adder = V.fixtures.alice_root
    const entries = V.keyring.epochs["1"].wrappedKeys
    const recipients = [V.fixtures.alice_dev_1, V.fixtures.alice_dev_2, V.fixtures.bob_root]

    for (let i = 0; i < entries.length; i++) {
      const recipient = recipients[i]
      const expected = entries[i]
      const ephPriv = await deterministicEphKey(cek, hexToBytes(recipient.kemPub))
      const iv = await deterministicIv(cek, hexToBytes(recipient.kemPub))
      const got = await wrapForRecipient(cek, recipient.kemPub, {
        adderEdPrivHex: adder.edPriv,
        adderEdPubHex: adder.edPub,
        addedAt: expected.addedAt,
        epoch: 1,
        ephPriv,
        iv,
      })
      expect(got).toEqual(expected)
    }
  })
})

describe("unwrapFromEntry — malformed entry", () => {
  it("rejects an entry whose ciphertext is shorter than the IV", async () => {
    // `ct` is `iv || aesgcm(...)`; a stub shorter than the 12-byte IV must be rejected
    // by the explicit length guard before the iv/ct split feeds AES-GCM. "AAAA" is the
    // base64 of 3 zero bytes — well under KEYRING_IV_BYTES.
    const malformed = { ...V.keyring.epochs["1"].wrappedKeys[0], ct: "AAAA" }
    await expect(
      unwrapFromEntry(malformed, V.fixtures.alice_dev_1.kemPriv),
    ).rejects.toThrow(/shorter than the IV/)
  })
})

// ── Signature verification ────────────────────────────────────────────────────

describe("verifyEntrySignature", () => {
  it("returns true for every entry in the vector keyring (epoch 1)", async () => {
    for (const entry of V.keyring.epochs["1"].wrappedKeys) {
      expect(await verifyEntrySignature(entry, 1)).toBe(true)
    }
  })

  it("returns false if epoch number is wrong", async () => {
    const entry = V.keyring.epochs["1"].wrappedKeys[0]
    expect(await verifyEntrySignature(entry, 2)).toBe(false)
  })

  it("returns false if ct is tampered", async () => {
    const entry = V.keyring.epochs["1"].wrappedKeys[0]
    const tampered: WrappedKeyEntry = { ...entry, ct: entry.ct.replace(/^./, "Z") }
    expect(await verifyEntrySignature(tampered, 1)).toBe(false)
  })
})

// ── Unwrap from entry ─────────────────────────────────────────────────────────

describe("unwrapFromEntry", () => {
  it("recovers the CEK for each vector recipient", async () => {
    const entries = V.keyring.epochs["1"].wrappedKeys
    const recipientsByPub = new Map(
      [V.fixtures.alice_dev_1, V.fixtures.alice_dev_2, V.fixtures.bob_root].map(
        (r) => [r.kemPub, r] as const,
      ),
    )
    for (const entry of entries) {
      const recipient = recipientsByPub.get(entry.subKem)
      expect(recipient).toBeDefined()
      const cek = await unwrapFromEntry(entry, recipient!.kemPriv)
      expect(bytesToHex(cek)).toBe(V.cek)
    }
  })

  it("throws when called with a non-matching recipient private key", async () => {
    const entry = V.keyring.epochs["1"].wrappedKeys[0]
    // Use bob's key instead of alice_dev_1's.
    await expect(unwrapFromEntry(entry, V.fixtures.bob_root.kemPriv)).rejects.toThrow()
  })
})

// ── Keyring lifecycle ─────────────────────────────────────────────────────────

describe("createKeyring → addRecipient → rotateEpoch", () => {
  const alice = V.fixtures.alice_root
  const dev1 = V.fixtures.alice_dev_1
  const dev2 = V.fixtures.alice_dev_2
  const bob = V.fixtures.bob_root

  it("createKeyring wraps the CEK for every recipient with valid signatures", async () => {
    const { keyring, cek } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }, { subKemHex: dev2.kemPub }],
    )
    expect(keyring.v).toBe(1)
    expect(keyring.currentEpoch).toBe(1)
    const wrapped = keyring.epochs["1"].wrappedKeys
    expect(wrapped).toHaveLength(2)
    for (const entry of wrapped) {
      expect(await verifyEntrySignature(entry, 1)).toBe(true)
    }
    // Recipients can recover the CEK.
    const cek1 = await unwrapFromEntry(wrapped[0], dev1.kemPriv)
    const cek2 = await unwrapFromEntry(wrapped[1], dev2.kemPriv)
    expect(bytesToHex(cek1)).toBe(bytesToHex(cek))
    expect(bytesToHex(cek2)).toBe(bytesToHex(cek))
  })

  it("addRecipient appends an entry to the current epoch", async () => {
    const { keyring, cek } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }],
    )
    const next = await addRecipient(
      keyring,
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      cek,
      dev2.kemPub,
    )
    expect(next.epochs["1"].wrappedKeys).toHaveLength(2)
    expect(next.epochs["1"].wrappedKeys[1].subKem).toBe(dev2.kemPub)
    const recovered = await unwrapFromEntry(next.epochs["1"].wrappedKeys[1], dev2.kemPriv)
    expect(bytesToHex(recovered)).toBe(bytesToHex(cek))
  })

  it("addRecipient throws for a duplicate subKem in the current epoch", async () => {
    const { keyring, cek } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }],
    )
    await expect(
      addRecipient(
        keyring,
        { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
        cek,
        dev1.kemPub,
      ),
    ).rejects.toThrow()
  })

  it("rotateEpoch creates a new epoch with only retained recipients", async () => {
    const { keyring, cek: cek1 } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }, { subKemHex: dev2.kemPub }, { subKemHex: bob.kemPub }],
    )
    const { keyring: rotated, cek: cek2 } = await rotateEpoch(
      keyring,
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }, { subKemHex: dev2.kemPub }],
    )
    expect(rotated.currentEpoch).toBe(2)
    expect(bytesToHex(cek1)).not.toBe(bytesToHex(cek2))
    expect(rotated.epochs["1"]).toBeDefined() // old epoch preserved
    expect(rotated.epochs["2"].wrappedKeys).toHaveLength(2)
    // Bob no longer present in epoch 2.
    for (const entry of rotated.epochs["2"].wrappedKeys) {
      expect(entry.subKem).not.toBe(bob.kemPub)
      expect(await verifyEntrySignature(entry, 2)).toBe(true)
    }
  })

  it("re-adding a rotated-out recipient restores access to the new epoch", async () => {
    // Churn: a recipient removed by a rotation can be re-granted access by adding
    // them back to the (new) current epoch. Mirrors test_keyring.py.
    const { keyring } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }, { subKemHex: dev2.kemPub }],
    )
    const { keyring: rotated, cek: cek2 } = await rotateEpoch(
      keyring,
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }], // dev2 rotated out
    )
    expect(rotated.epochs["2"].wrappedKeys.some((e) => e.subKem === dev2.kemPub)).toBe(false)

    const readded = await addRecipient(
      rotated,
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      cek2,
      dev2.kemPub,
    )
    const entry = readded.epochs["2"].wrappedKeys.find((e) => e.subKem === dev2.kemPub)!
    expect(bytesToHex(await unwrapFromEntry(entry, dev2.kemPriv))).toBe(bytesToHex(cek2))
  })

  it("rotating out every recipient yields an empty epoch whose encryptor fails for a former recipient", async () => {
    const { keyring } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }],
    )
    const { keyring: emptied } = await rotateEpoch(
      keyring,
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [], // retain nobody
    )
    expect(emptied.currentEpoch).toBe(2)
    expect(emptied.epochs["2"].wrappedKeys).toHaveLength(0)
    await expect(
      createKeyringEncryptor(
        emptied,
        { kemPubHex: dev1.kemPub, kemPrivHex: dev1.kemPriv },
        { trustedAdders: [alice.edPub] },
      ),
    ).rejects.toThrow()
  })
})

// ── Encryptor round-trip ──────────────────────────────────────────────────────

describe("createKeyringEncryptor", () => {
  const alice = V.fixtures.alice_root
  const dev1 = V.fixtures.alice_dev_1
  const dev2 = V.fixtures.alice_dev_2
  const bob = V.fixtures.bob_root

  it("encrypts on one device and decrypts on another", async () => {
    const { keyring } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }, { subKemHex: dev2.kemPub }],
    )
    const enc1 = await createKeyringEncryptor(keyring, { kemPubHex: dev1.kemPub, kemPrivHex: dev1.kemPriv }, { trustedAdders: [alice.edPub] })
    const enc2 = await createKeyringEncryptor(keyring, { kemPubHex: dev2.kemPub, kemPrivHex: dev2.kemPriv }, { trustedAdders: [alice.edPub] })

    const payload = await enc1.encrypt({ hello: "world", n: 7 })
    expect(typeof payload._encrypted).toBe("string")
    expect(payload._epoch).toBe(1)
    const decrypted = await enc2.decrypt(payload)
    expect(decrypted).toEqual({ hello: "world", n: 7 })
  })

  it("sealBytes round-trips raw bytes across devices", async () => {
    const { keyring } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }, { subKemHex: dev2.kemPub }],
    )
    const enc1 = await createKeyringEncryptor(keyring, { kemPubHex: dev1.kemPub, kemPrivHex: dev1.kemPriv }, { trustedAdders: [alice.edPub] })
    const enc2 = await createKeyringEncryptor(keyring, { kemPubHex: dev2.kemPub, kemPrivHex: dev2.kemPriv }, { trustedAdders: [alice.edPub] })

    const data = new Uint8Array([0, 1, 2, 250, 251, 255, 7, 7])
    const blob = await enc1.sealBytes(data, "attachments/rooms/r1/blob1")
    expect(blob[3]).toBe(1) // epoch 1 in the big-endian header
    expect(blob.length).toBeGreaterThan(4 + KEYRING_IV_BYTES + data.length) // + GCM tag
    const opened = await enc2.openBytes(blob, "attachments/rooms/r1/blob1")
    expect(Array.from(opened)).toEqual(Array.from(data))
  })

  it("openBytes rejects an AAD (path) mismatch", async () => {
    const { keyring } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }],
    )
    const enc = await createKeyringEncryptor(keyring, { kemPubHex: dev1.kemPub, kemPrivHex: dev1.kemPriv }, { trustedAdders: [alice.edPub] })
    const blob = await enc.sealBytes(new Uint8Array([9, 9, 9]), "attachments/rooms/r1/blobA")
    await expect(enc.openBytes(blob, "attachments/rooms/r1/blobB")).rejects.toThrow(/decryption failed/i)
  })

  it("rejects an epoch rollback when minEpoch is supplied", async () => {
    const { keyring } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }],
    )
    const { keyring: rotated } = await rotateEpoch(
      keyring,
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }],
    )
    expect(rotated.currentEpoch).toBe(2)
    // At/above the floor → fine.
    await createKeyringEncryptor(
      rotated,
      { kemPubHex: dev1.kemPub, kemPrivHex: dev1.kemPriv },
      { trustedAdders: [alice.edPub], minEpoch: 2 },
    )
    // A rolled-back keyring (epoch 1) presented when the caller has seen epoch 2 → rejected.
    await expect(
      createKeyringEncryptor(
        keyring,
        { kemPubHex: dev1.kemPub, kemPrivHex: dev1.kemPriv },
        { trustedAdders: [alice.edPub], minEpoch: 2 },
      ),
    ).rejects.toThrow(/rollback/)
  })

  it("falls back to currentEpoch when _epoch is missing on the payload", async () => {
    const { keyring } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }],
    )
    const enc = await createKeyringEncryptor(keyring, { kemPubHex: dev1.kemPub, kemPrivHex: dev1.kemPriv }, { trustedAdders: [alice.edPub] })
    const wrapped = await enc.encrypt({ a: 1 })
    const { _epoch, ...withoutEpoch } = wrapped
    void _epoch
    const decrypted = await enc.decrypt(withoutEpoch as { _encrypted: string })
    expect(decrypted).toEqual({ a: 1 })
  })

  it("a removed recipient cannot decrypt new-epoch documents", async () => {
    const { keyring } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }, { subKemHex: bob.kemPub }],
    )
    // Bob builds an encryptor while still in the keyring.
    const bobOldEnc = await createKeyringEncryptor(keyring, {
      kemPubHex: bob.kemPub,
      kemPrivHex: bob.kemPriv,
    }, { trustedAdders: [alice.edPub] })

    // Rotation excludes bob.
    const { keyring: rotated } = await rotateEpoch(
      keyring,
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }],
    )
    const aliceEnc = await createKeyringEncryptor(rotated, {
      kemPubHex: dev1.kemPub,
      kemPrivHex: dev1.kemPriv,
    }, { trustedAdders: [alice.edPub] })
    const payload = await aliceEnc.encrypt({ secret: "for-alice-only" })
    expect(payload._epoch).toBe(2)

    // Bob's old encryptor has no key for epoch 2.
    await expect(bobOldEnc.decrypt(payload)).rejects.toThrow()

    // And bob cannot construct a fresh encryptor from the rotated keyring.
    await expect(
      createKeyringEncryptor(rotated, { kemPubHex: bob.kemPub, kemPrivHex: bob.kemPriv }, { trustedAdders: [alice.edPub] }),
    ).rejects.toThrow()
  })

  it("decrypt with a known x25519 round-trip matches @noble shared secret", async () => {
    // Sanity check: ECDH between two parties yields the same shared secret regardless of direction.
    const a = x25519.utils.randomSecretKey()
    const b = x25519.utils.randomSecretKey()
    const aPub = x25519.getPublicKey(a)
    const bPub = x25519.getPublicKey(b)
    const sa = x25519.getSharedSecret(a, bPub)
    const sb = x25519.getSharedSecret(b, aPub)
    expect(bytesToHex(sa)).toBe(bytesToHex(sb))
  })

  it("skips an entry whose addedBy was tampered post-wrap (audit-sig fails)", async () => {
    // Two recipients in epoch 1; mutate dev1's `addedBy` to a different
    // Ed25519 pubkey so its `addedSig` no longer verifies. The encryptor
    // for dev1 must NOT silently trust the unwrap — verifyEntrySignature
    // is consulted before unwrap, so the epoch is skipped and the
    // recipient is locked out of that epoch.
    const { keyring } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }, { subKemHex: dev2.kemPub }],
    )
    const tampered: Keyring = {
      ...keyring,
      epochs: {
        ...keyring.epochs,
        "1": {
          ...keyring.epochs["1"],
          wrappedKeys: keyring.epochs["1"].wrappedKeys.map((e) =>
            e.subKem === dev1.kemPub ? { ...e, addedBy: bob.edPub } : e,
          ),
        },
      },
    }
    await expect(
      createKeyringEncryptor(tampered, { kemPubHex: dev1.kemPub, kemPrivHex: dev1.kemPriv }, { trustedAdders: [alice.edPub] }),
    ).rejects.toThrow(/No wrapped key for recipient/)
  })

  it("skips a tampered entry in epoch N but keeps usable entries in other epochs", async () => {
    // Recipient is in epochs 1 and 2; tamper with the epoch-1 entry only.
    // The encryptor should still be usable for epoch 2 (currentEpoch) and
    // simply lack a CEK for epoch 1.
    const { keyring } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }],
    )
    const { keyring: rotated } = await rotateEpoch(
      keyring,
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }],
    )
    // Mutate epoch 1's entry for dev1.
    const tampered: Keyring = {
      ...rotated,
      epochs: {
        ...rotated.epochs,
        "1": {
          ...rotated.epochs["1"],
          wrappedKeys: rotated.epochs["1"].wrappedKeys.map((e) =>
            e.subKem === dev1.kemPub ? { ...e, addedBy: bob.edPub } : e,
          ),
        },
      },
    }
    const enc = await createKeyringEncryptor(tampered, {
      kemPubHex: dev1.kemPub,
      kemPrivHex: dev1.kemPriv,
    }, { trustedAdders: [alice.edPub] })
    const payload = await enc.encrypt({ value: 42 })
    expect(payload._epoch).toBe(2)
    expect(await enc.decrypt(payload)).toEqual({ value: 42 })
  })

  it("a recipient added after a rotation can't read old-epoch content until it is re-sealed", async () => {
    // dev1 + bob start in epoch 1; dev1 seals a document there.
    const { keyring } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }, { subKemHex: bob.kemPub }],
    )
    const enc1 = await createKeyringEncryptor(keyring, { kemPubHex: dev1.kemPub, kemPrivHex: dev1.kemPriv }, { trustedAdders: [alice.edPub] })
    const oldDoc = await enc1.encrypt({ msg: "history" })
    expect(oldDoc._epoch).toBe(1)

    // Revoking bob rotates to epoch 2 — the old doc stays sealed under epoch 1.
    const { keyring: rotated, cek: cek2 } = await rotateEpoch(
      keyring,
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }],
    )
    // A NEW device (dev2) is then added — to the current epoch (2) ONLY.
    const withDev2 = await addRecipient(
      rotated,
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      cek2,
      dev2.kemPub,
    )

    // dev2 builds an encryptor fine (it IS in the current epoch)…
    const dev2Enc = await createKeyringEncryptor(withDev2, { kemPubHex: dev2.kemPub, kemPrivHex: dev2.kemPriv }, { trustedAdders: [alice.edPub] })
    // …but cannot read the epoch-1 history.
    await expect(dev2Enc.decrypt(oldDoc)).rejects.toThrow(/No key available for epoch 1/)

    // An existing recipient present in BOTH epochs re-seals the doc at the
    // current epoch (what the app does after adding a recipient).
    const reSealer = await createKeyringEncryptor(withDev2, { kemPubHex: dev1.kemPub, kemPrivHex: dev1.kemPriv }, { trustedAdders: [alice.edPub] })
    const reSealed = await reSealer.encrypt(await reSealer.decrypt(oldDoc))
    expect(reSealed._epoch).toBe(2)
    // Now the freshly-added device can read it.
    expect(await dev2Enc.decrypt(reSealed)).toEqual({ msg: "history" })
  })
})

describe("createKeyringEncryptor rejects keyring tampering (hostile server)", () => {
  const alice = V.fixtures.alice_root // owner / trusted adder
  const dev1 = V.fixtures.alice_dev_1 // recipient
  const dev2 = V.fixtures.alice_dev_2
  const attacker = V.fixtures.bob_root // NOT the owner

  it("fails closed when a SECOND entry is injected for the recipient's subKem", async () => {
    // The audit signature is self-attesting: an attacker can sign their own
    // forged entry with their own key. First-match selection would let a
    // prepended attacker entry override the recipient's real CEK. A valid
    // epoch has at most one entry per subKem, so a duplicate is tampering.
    const { keyring } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }, { subKemHex: dev2.kemPub }],
    )
    const attackerCek = new Uint8Array(32).fill(0xaa)
    const forged = await wrapForRecipient(attackerCek, dev1.kemPub, {
      adderEdPrivHex: attacker.edPriv,
      adderEdPubHex: attacker.edPub,
      addedAt: Math.floor(Date.now() / 1000),
      epoch: 1,
    })
    const tampered: Keyring = {
      ...keyring,
      epochs: {
        ...keyring.epochs,
        "1": {
          ...keyring.epochs["1"],
          // Prepend so a naive first-match would pick the attacker's entry.
          wrappedKeys: [forged, ...keyring.epochs["1"].wrappedKeys],
        },
      },
    }
    await expect(
      createKeyringEncryptor(tampered, { kemPubHex: dev1.kemPub, kemPrivHex: dev1.kemPriv }, { trustedAdders: [alice.edPub] }),
    ).rejects.toThrow(/No wrapped key for recipient/)
  })

  it("with trustedAdders, rejects a REPLACED entry whose addedBy is not trusted", async () => {
    const { keyring } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }],
    )
    const attackerCek = new Uint8Array(32).fill(0xbb)
    const forged = await wrapForRecipient(attackerCek, dev1.kemPub, {
      adderEdPrivHex: attacker.edPriv,
      adderEdPubHex: attacker.edPub,
      addedAt: Math.floor(Date.now() / 1000),
      epoch: 1,
    })
    // Replace the legit entry entirely — no duplicate subKem, so only adder
    // provenance can catch it. The forged entry's self-signature verifies.
    const tampered: Keyring = {
      ...keyring,
      epochs: { ...keyring.epochs, "1": { ...keyring.epochs["1"], wrappedKeys: [forged] } },
    }
    await expect(
      createKeyringEncryptor(
        tampered,
        { kemPubHex: dev1.kemPub, kemPrivHex: dev1.kemPriv },
        { trustedAdders: [alice.edPub] },
      ),
    ).rejects.toThrow(/No wrapped key for recipient/)
  })

  it("with trustedAdders, an owner-added entry still resolves (no over-rejection)", async () => {
    const { keyring } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }],
    )
    const enc = await createKeyringEncryptor(
      keyring,
      { kemPubHex: dev1.kemPub, kemPrivHex: dev1.kemPriv },
      { trustedAdders: [alice.edPub] },
    )
    const payload = await enc.encrypt({ ok: true })
    expect(await enc.decrypt(payload)).toEqual({ ok: true })
  })

  it("fails closed: throws when trustedAdders is omitted", async () => {
    const { keyring } = await createKeyring(
      { edPrivHex: alice.edPriv, edPubHex: alice.edPub },
      [{ subKemHex: dev1.kemPub }],
    )
    // No trustedAdders → reject rather than silently run without provenance.
    await expect(
      createKeyringEncryptor(keyring, { kemPubHex: dev1.kemPub, kemPrivHex: dev1.kemPriv }),
    ).rejects.toThrow(/trustedAdders/)
    await expect(
      createKeyringEncryptor(keyring, { kemPubHex: dev1.kemPub, kemPrivHex: dev1.kemPriv }, { trustedAdders: [] }),
    ).rejects.toThrow(/trustedAdders/)
  })
})
