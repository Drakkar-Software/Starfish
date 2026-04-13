import { describe, it, expect, beforeAll } from "vitest"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import {
  deriveGroupKeyPair,
  generateGroupKey,
  wrapGroupKey,
  unwrapGroupKey,
  createGroupKeyring,
  addGroupMember,
  rotateGroupKey,
  createGroupEncryptor,
  type GroupKeyPair,
} from "../src/group-crypto.js"
import { deriveCredentials } from "../src/identity.js"
import vectors from "../../../../tests/test-vectors/group-crypto.json"

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

// ── deriveGroupKeyPair ────────────────────────────────────────────────────────

describe("deriveGroupKeyPair", () => {
  it("returns private and public keys as 64-char hex strings (32 bytes)", async () => {
    const kp = await deriveGroupKeyPair("hello world", "abc123")
    expect(kp.privateKey).toMatch(/^[0-9a-f]{64}$/)
    expect(kp.publicKey).toMatch(/^[0-9a-f]{64}$/)
  })

  it("is deterministic — same inputs always yield same key pair", async () => {
    const a = await deriveGroupKeyPair("my passphrase", "userid123")
    const b = await deriveGroupKeyPair("my passphrase", "userid123")
    expect(a.privateKey).toBe(b.privateKey)
    expect(a.publicKey).toBe(b.publicKey)
  })

  it("different passphrases yield different key pairs", async () => {
    const a = await deriveGroupKeyPair("passphrase-a", "user1")
    const b = await deriveGroupKeyPair("passphrase-b", "user1")
    expect(a.privateKey).not.toBe(b.privateKey)
    expect(a.publicKey).not.toBe(b.publicKey)
  })

  it("different userIds yield different key pairs", async () => {
    const a = await deriveGroupKeyPair("same passphrase", "user1")
    const b = await deriveGroupKeyPair("same passphrase", "user2")
    expect(a.publicKey).not.toBe(b.publicKey)
  })

  it("public and private keys are distinct", async () => {
    const kp = await deriveGroupKeyPair("test phrase", "testuser")
    expect(kp.publicKey).not.toBe(kp.privateKey)
  })
})

// ── generateGroupKey ─────────────────────────────────────────────────────────

describe("generateGroupKey", () => {
  it("returns a 64-char hex string (32 bytes)", () => {
    const gek = generateGroupKey()
    expect(gek).toMatch(/^[0-9a-f]{64}$/)
  })

  it("generates different keys on each call", () => {
    const keys = new Set(Array.from({ length: 10 }, () => generateGroupKey()))
    expect(keys.size).toBe(10)
  })
})

// ── wrapGroupKey / unwrapGroupKey ─────────────────────────────────────────────

describe("wrapGroupKey / unwrapGroupKey", () => {
  it("wraps and unwraps a GEK successfully (ECDH round-trip)", async () => {
    const adminKp = await deriveGroupKeyPair("admin passphrase", "adminId")
    const memberKp = await deriveGroupKeyPair("member passphrase", "memberId")
    const gek = generateGroupKey()

    const wrapped = await wrapGroupKey(gek, memberKp.publicKey, adminKp.privateKey)
    const unwrapped = await unwrapGroupKey(wrapped, memberKp.privateKey, adminKp.publicKey)

    expect(unwrapped).toBe(gek)
  })

  it("wrapped value is a non-empty base64 string", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "a1")
    const memberKp = await deriveGroupKeyPair("member", "m1")
    const gek = generateGroupKey()
    const wrapped = await wrapGroupKey(gek, memberKp.publicKey, adminKp.privateKey)
    expect(typeof wrapped).toBe("string")
    expect(wrapped.length).toBeGreaterThan(0)
  })

  it("each wrap call produces a different ciphertext (random IV)", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "a1")
    const memberKp = await deriveGroupKeyPair("member", "m1")
    const gek = generateGroupKey()
    const wrapped1 = await wrapGroupKey(gek, memberKp.publicKey, adminKp.privateKey)
    const wrapped2 = await wrapGroupKey(gek, memberKp.publicKey, adminKp.privateKey)
    expect(wrapped1).not.toBe(wrapped2)
  })

  it("unwrapping with wrong private key throws", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "a1")
    const memberKp = await deriveGroupKeyPair("member", "m1")
    const wrongKp = await deriveGroupKeyPair("wrong", "w1")
    const gek = generateGroupKey()
    const wrapped = await wrapGroupKey(gek, memberKp.publicKey, adminKp.privateKey)

    await expect(
      unwrapGroupKey(wrapped, wrongKp.privateKey, adminKp.publicKey),
    ).rejects.toThrow()
  })

  it("unwrapping with wrong admin public key throws", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "a1")
    const memberKp = await deriveGroupKeyPair("member", "m1")
    const wrongKp = await deriveGroupKeyPair("wrong", "w1")
    const gek = generateGroupKey()
    const wrapped = await wrapGroupKey(gek, memberKp.publicKey, adminKp.privateKey)

    await expect(
      unwrapGroupKey(wrapped, memberKp.privateKey, wrongKp.publicKey),
    ).rejects.toThrow()
  })
})

// ── createGroupKeyring ────────────────────────────────────────────────────────

describe("createGroupKeyring", () => {
  it("creates a keyring with currentEpoch=1 and wrapped keys for all members", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "admin1")
    const aliceKp = await deriveGroupKeyPair("alice", "alice1")
    const bobKp = await deriveGroupKeyPair("bob", "bob1")
    const { keyring, gek } = await createGroupKeyring(adminKp, {
      alice: aliceKp.publicKey,
      bob: bobKp.publicKey,
    })

    expect(keyring.currentEpoch).toBe(1)
    expect(keyring.epochs["1"]).toBeDefined()
    expect(keyring.epochs["1"].wrappedKeys["alice"]).toBeDefined()
    expect(keyring.epochs["1"].wrappedKeys["bob"]).toBeDefined()
    expect(gek).toMatch(/^[0-9a-f]{64}$/)
  })

  it("all members can unwrap the GEK from the keyring", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "a")
    const aliceKp = await deriveGroupKeyPair("alice", "a")
    const { keyring, gek } = await createGroupKeyring(adminKp, { alice: aliceKp.publicKey })

    const aliceGek = await unwrapGroupKey(
      keyring.epochs["1"].wrappedKeys["alice"],
      aliceKp.privateKey,
      keyring.epochs["1"].adminPublicKey,
    )
    expect(aliceGek).toBe(gek)
  })

  it("accepts an explicit GEK", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "a")
    const aliceKp = await deriveGroupKeyPair("alice", "a")
    const myGek = generateGroupKey()
    const { gek } = await createGroupKeyring(adminKp, { alice: aliceKp.publicKey }, myGek)
    expect(gek).toBe(myGek)
  })
})

// ── addGroupMember ────────────────────────────────────────────────────────────

describe("addGroupMember", () => {
  it("adds a new member who can then unwrap the GEK", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "adm")
    const aliceKp = await deriveGroupKeyPair("alice", "ali")
    const charlieKp = await deriveGroupKeyPair("charlie", "cha")
    const { keyring, gek } = await createGroupKeyring(adminKp, { alice: aliceKp.publicKey })

    const updated = await addGroupMember(keyring, adminKp, gek, "charlie", charlieKp.publicKey)
    expect(updated.epochs["1"].wrappedKeys["charlie"]).toBeDefined()

    const charlieGek = await unwrapGroupKey(
      updated.epochs["1"].wrappedKeys["charlie"],
      charlieKp.privateKey,
      updated.epochs["1"].adminPublicKey,
    )
    expect(charlieGek).toBe(gek)
  })

  it("throws if the key pair does not match the epoch admin public key", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "a")
    const wrongKp = await deriveGroupKeyPair("wrong", "w")
    const aliceKp = await deriveGroupKeyPair("alice", "b")
    const { keyring, gek } = await createGroupKeyring(adminKp, { alice: aliceKp.publicKey })

    await expect(
      addGroupMember(keyring, wrongKp, gek, "new", aliceKp.publicKey),
    ).rejects.toThrow(/does not match/)
  })
})

// ── rotateGroupKey ────────────────────────────────────────────────────────────

describe("rotateGroupKey", () => {
  it("creates a new epoch with incremented number", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "a")
    const aliceKp = await deriveGroupKeyPair("alice", "a")
    const bobKp = await deriveGroupKeyPair("bob", "b")
    const { keyring } = await createGroupKeyring(adminKp, {
      alice: aliceKp.publicKey,
      bob: bobKp.publicKey,
    })

    const { keyring: rotated, gek: newGek } = await rotateGroupKey(keyring, adminKp, {
      alice: aliceKp.publicKey,
    })

    expect(rotated.currentEpoch).toBe(2)
    expect(rotated.epochs["1"]).toBeDefined()  // old epoch preserved
    expect(rotated.epochs["2"]).toBeDefined()  // new epoch
    expect(rotated.epochs["2"].wrappedKeys["alice"]).toBeDefined()
    expect(rotated.epochs["2"].wrappedKeys["bob"]).toBeUndefined()  // removed
    expect(newGek).toMatch(/^[0-9a-f]{64}$/)
  })

  it("removed member cannot unwrap new epoch GEK", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "a")
    const bobKp = await deriveGroupKeyPair("bob", "b")
    const { keyring } = await createGroupKeyring(adminKp, { bob: bobKp.publicKey })

    const { keyring: rotated } = await rotateGroupKey(keyring, adminKp, {})

    // bob has no entry in epoch 2
    expect(rotated.epochs["2"].wrappedKeys["bob"]).toBeUndefined()
  })

  it("throws if the key pair does not match the epoch admin public key", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "a")
    const wrongKp = await deriveGroupKeyPair("wrong", "w")
    const aliceKp = await deriveGroupKeyPair("alice", "b")
    const { keyring } = await createGroupKeyring(adminKp, { alice: aliceKp.publicKey })

    await expect(
      rotateGroupKey(keyring, wrongKp, { alice: aliceKp.publicKey }),
    ).rejects.toThrow(/does not match/)
  })
})

// ── createGroupEncryptor ──────────────────────────────────────────────────────

describe("createGroupEncryptor", () => {
  it("encrypts and decrypts data correctly", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "a")
    const aliceKp = await deriveGroupKeyPair("alice", "a")
    const { keyring } = await createGroupKeyring(adminKp, { alice: aliceKp.publicKey })

    const encryptor = await createGroupEncryptor(keyring, "alice", aliceKp.privateKey)
    const plaintext = { message: "hello group", ts: 12345 }
    const encrypted = await encryptor.encrypt(plaintext)
    const decrypted = await encryptor.decrypt(encrypted)

    expect(decrypted).toEqual(plaintext)
  })

  it("encrypted data includes _epoch field", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "a")
    const aliceKp = await deriveGroupKeyPair("alice", "a")
    const { keyring } = await createGroupKeyring(adminKp, { alice: aliceKp.publicKey })

    const encryptor = await createGroupEncryptor(keyring, "alice", aliceKp.privateKey)
    const encrypted = await encryptor.encrypt({ x: 1 })
    expect(encrypted["_epoch"]).toBe(1)
  })

  it("decrypts documents from older epochs", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "a")
    const aliceKp = await deriveGroupKeyPair("alice", "a")
    const { keyring } = await createGroupKeyring(adminKp, { alice: aliceKp.publicKey })

    // Encrypt with epoch 1
    const enc1 = await createGroupEncryptor(keyring, "alice", aliceKp.privateKey)
    const old = await enc1.encrypt({ era: "epoch-1" })
    expect(old["_epoch"]).toBe(1)

    // Rotate — alice stays
    const { keyring: rotated } = await rotateGroupKey(keyring, adminKp, { alice: aliceKp.publicKey })

    // Create encryptor on new keyring — has keys for both epochs
    const enc2 = await createGroupEncryptor(rotated, "alice", aliceKp.privateKey)

    // New encryptions use epoch 2
    const newDoc = await enc2.encrypt({ era: "epoch-2" })
    expect(newDoc["_epoch"]).toBe(2)

    // Can still decrypt old epoch-1 doc
    const oldDecrypted = await enc2.decrypt(old)
    expect(oldDecrypted).toEqual({ era: "epoch-1" })
  })

  it("throws for unknown identity", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "a")
    const aliceKp = await deriveGroupKeyPair("alice", "a")
    const { keyring } = await createGroupKeyring(adminKp, { alice: aliceKp.publicKey })

    await expect(
      createGroupEncryptor(keyring, "nobody", aliceKp.privateKey),
    ).rejects.toThrow(/No wrapped key found/)
  })

  it("throws when decrypting with epoch not present in keyring", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "a")
    const aliceKp = await deriveGroupKeyPair("alice", "a")
    const { keyring } = await createGroupKeyring(adminKp, { alice: aliceKp.publicKey })

    const encryptor = await createGroupEncryptor(keyring, "alice", aliceKp.privateKey)
    const fakeDoc = { _encrypted: "not-real", _epoch: 99 }
    await expect(encryptor.decrypt(fakeDoc)).rejects.toThrow(/No key available for epoch/)
  })

  it("falls back to currentEpoch when _epoch is absent from a document", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "a")
    const aliceKp = await deriveGroupKeyPair("alice", "a")
    const { keyring } = await createGroupKeyring(adminKp, { alice: aliceKp.publicKey })

    const encryptor = await createGroupEncryptor(keyring, "alice", aliceKp.privateKey)
    const plaintext = { msg: "legacy doc" }

    // Encrypt normally (has _epoch), then strip _epoch to simulate a legacy document
    const encrypted = await encryptor.encrypt(plaintext)
    const { _epoch: _removed, ...withoutEpoch } = encrypted
    const decrypted = await encryptor.decrypt(withoutEpoch)
    expect(decrypted).toEqual(plaintext)
  })

  it("two members can cross-decrypt each other's messages", async () => {
    const adminKp = await deriveGroupKeyPair("admin", "a")
    const aliceKp = await deriveGroupKeyPair("alice", "a")
    const bobKp = await deriveGroupKeyPair("bob", "b")
    const { keyring } = await createGroupKeyring(adminKp, {
      alice: aliceKp.publicKey,
      bob: bobKp.publicKey,
    })

    const aliceEnc = await createGroupEncryptor(keyring, "alice", aliceKp.privateKey)
    const bobEnc = await createGroupEncryptor(keyring, "bob", bobKp.privateKey)

    const aliceMsg = await aliceEnc.encrypt({ from: "alice", text: "hi" })
    const bobDecrypted = await bobEnc.decrypt(aliceMsg)
    expect(bobDecrypted).toEqual({ from: "alice", text: "hi" })

    const bobMsg = await bobEnc.encrypt({ from: "bob", text: "hey" })
    const aliceDecrypted = await aliceEnc.decrypt(bobMsg)
    expect(aliceDecrypted).toEqual({ from: "bob", text: "hey" })
  })
})

// ── deriveCredentials integration ─────────────────────────────────────────────

describe("deriveCredentials includes group key pair", () => {
  it("returns groupPublicKey and groupPrivateKey", async () => {
    const creds = await deriveCredentials("my test passphrase")
    expect(creds.groupPublicKey).toMatch(/^[0-9a-f]{64}$/)
    expect(creds.groupPrivateKey).toMatch(/^[0-9a-f]{64}$/)
  })

  it("group keys are deterministic", async () => {
    const a = await deriveCredentials("same passphrase xyz")
    const b = await deriveCredentials("same passphrase xyz")
    expect(a.groupPublicKey).toBe(b.groupPublicKey)
    expect(a.groupPrivateKey).toBe(b.groupPrivateKey)
  })

  it("group public key differs from other credential fields", async () => {
    const creds = await deriveCredentials("test pass")
    expect(creds.groupPublicKey).not.toBe(creds.authToken)
    expect(creds.groupPublicKey).not.toBe(creds.encryptionSecret)
  })

  it("can use deriveCredentials output directly with createGroupKeyring", async () => {
    const adminCreds = await deriveCredentials("admin passphrase")
    const aliceCreds = await deriveCredentials("alice passphrase")

    const { keyring, gek } = await createGroupKeyring(
      { publicKey: adminCreds.groupPublicKey, privateKey: adminCreds.groupPrivateKey },
      { [aliceCreds.userId]: aliceCreds.groupPublicKey },
    )

    const encryptor = await createGroupEncryptor(keyring, aliceCreds.userId, aliceCreds.groupPrivateKey)
    const encrypted = await encryptor.encrypt({ msg: "hello" })
    const decrypted = await encryptor.decrypt(encrypted)
    expect(decrypted).toEqual({ msg: "hello" })
  })
})

// ── Cross-language test vectors ───────────────────────────────────────────────

describe("cross-language test vectors", () => {
  it("deriveGroupKeyPair matches Python-generated admin vector", async () => {
    const v = vectors.keypairs.admin
    const kp = await deriveGroupKeyPair(v.passphrase, v.userId)
    expect(kp.privateKey).toBe(v.privateKey)
    expect(kp.publicKey).toBe(v.publicKey)
  })

  it("deriveGroupKeyPair matches Python-generated alice vector", async () => {
    const v = vectors.keypairs.alice
    const kp = await deriveGroupKeyPair(v.passphrase, v.userId)
    expect(kp.privateKey).toBe(v.privateKey)
    expect(kp.publicKey).toBe(v.publicKey)
  })

  it("deriveGroupKeyPair matches Python-generated bob vector", async () => {
    const v = vectors.keypairs.bob
    const kp = await deriveGroupKeyPair(v.passphrase, v.userId)
    expect(kp.privateKey).toBe(v.privateKey)
    expect(kp.publicKey).toBe(v.publicKey)
  })

  it("unwraps Python-generated alice wrapped key to the fixed GEK", async () => {
    const w = vectors.wrapping
    const kp = vectors.keypairs
    const recovered = await unwrapGroupKey(w.wrappedForAlice, kp.alice.privateKey, kp.admin.publicKey)
    expect(recovered).toBe(w.gek)
  })

  it("unwraps Python-generated bob wrapped key to the fixed GEK", async () => {
    const w = vectors.wrapping
    const kp = vectors.keypairs
    const recovered = await unwrapGroupKey(w.wrappedForBob, kp.bob.privateKey, kp.admin.publicKey)
    expect(recovered).toBe(w.gek)
  })

  it("wraps a GEK with vector keys then unwraps it — full TS round-trip with vector keys", async () => {
    const kp = vectors.keypairs
    const gek = vectors.wrapping.gek
    const wrapped = await wrapGroupKey(gek, kp.alice.publicKey, kp.admin.privateKey)
    const recovered = await unwrapGroupKey(wrapped, kp.alice.privateKey, kp.admin.publicKey)
    expect(recovered).toBe(gek)
  })

  it("both members can decrypt a document encrypted with the fixed GEK keyring", async () => {
    const kpData = vectors.keypairs
    const w = vectors.wrapping

    const adminKp: GroupKeyPair = { privateKey: kpData.admin.privateKey, publicKey: kpData.admin.publicKey }
    const aliceKp: GroupKeyPair = { privateKey: kpData.alice.privateKey, publicKey: kpData.alice.publicKey }
    const bobKp: GroupKeyPair = { privateKey: kpData.bob.privateKey, publicKey: kpData.bob.publicKey }

    const { keyring, gek } = await createGroupKeyring(
      adminKp,
      { alice: aliceKp.publicKey, bob: bobKp.publicKey },
      w.gek,
    )
    expect(gek).toBe(w.gek)

    const aliceEnc = await createGroupEncryptor(keyring, "alice", aliceKp.privateKey)
    const bobEnc = await createGroupEncryptor(keyring, "bob", bobKp.privateKey)

    const plaintext = { msg: "cross-lang test", n: 42 }
    const encrypted = await aliceEnc.encrypt(plaintext)
    expect(encrypted["_epoch"]).toBe(1)

    expect(await bobEnc.decrypt(encrypted)).toEqual(plaintext)
    expect(await aliceEnc.decrypt(encrypted)).toEqual(plaintext)
  })

  it("decrypts a document encrypted by Python (cross-language data vector)", async () => {
    const kpData = vectors.keypairs
    const w = vectors.wrapping
    const d = vectors.dataEncryption

    const adminKp: GroupKeyPair = { privateKey: kpData.admin.privateKey, publicKey: kpData.admin.publicKey }
    const aliceKp: GroupKeyPair = { privateKey: kpData.alice.privateKey, publicKey: kpData.alice.publicKey }
    const bobKp: GroupKeyPair = { privateKey: kpData.bob.privateKey, publicKey: kpData.bob.publicKey }

    const { keyring } = await createGroupKeyring(
      adminKp,
      { alice: aliceKp.publicKey, bob: bobKp.publicKey },
      w.gek,
    )

    // Both alice and bob must be able to decrypt the Python-produced blob
    const aliceEnc = await createGroupEncryptor(keyring, "alice", aliceKp.privateKey)
    const bobEnc = await createGroupEncryptor(keyring, "bob", bobKp.privateKey)

    expect(await aliceEnc.decrypt(d.encryptedByPython)).toEqual(d.plaintext)
    expect(await bobEnc.decrypt(d.encryptedByPython)).toEqual(d.plaintext)
  })
})
