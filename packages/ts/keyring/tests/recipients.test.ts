import { describe, it, expect, beforeAll, vi } from "vitest"
import { configurePlatform, getSuite } from "@drakkar.software/starfish-protocol"
import { x25519, ed25519 } from "@noble/curves/ed25519.js"
import {
  createKeyring,
  addRecipient,
  unwrapFromEntry,
  wrapForRecipient,
  type Keyring,
} from "../src/keyring.js"
import {
  keyringPathFor,
  addRecipient as addRecipientToCollection,
  removeRecipient,
  listRecipients,
  currentEpoch,
} from "../src/recipients.js"
import { StarfishHttpError, type StarfishClient } from "@drakkar.software/starfish-client"

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

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
}

interface TestParty {
  edPriv: string
  edPub: string
  kemPriv: string
  kemPub: string
}

function makeParty(): TestParty {
  const edPriv = ed25519.utils.randomSecretKey()
  const edPub = ed25519.getPublicKey(edPriv)
  const kemPriv = x25519.utils.randomSecretKey()
  const kemPub = x25519.getPublicKey(kemPriv)
  return {
    edPriv: bytesToHex(edPriv),
    edPub: bytesToHex(edPub),
    kemPriv: bytesToHex(kemPriv),
    kemPub: bytesToHex(kemPub),
  }
}

/** A secp256k1 party — one key does both signing and KEM (Nostr convention). */
function makeSecpParty(): TestParty {
  const k = getSuite("secp256k1-schnorr").generateKemKeypair()
  return { edPriv: k.privHex, edPub: k.pubHex, kemPriv: k.privHex, kemPub: k.pubHex }
}

/** Mock StarfishClient that stores a single Keyring document in memory keyed by path. */
function makeMockClient(initial?: { path: string; data: Keyring; hash: string }) {
  const store = new Map<string, { data: Keyring; hash: string }>()
  if (initial) store.set(initial.path, { data: initial.data, hash: initial.hash })
  let counter = initial ? 1 : 0

  const client = {
    pull: vi.fn(async (path: string) => {
      const entry = store.get(path)
      if (!entry) throw new StarfishHttpError(404, "not found")
      return { data: entry.data as unknown as Record<string, unknown>, hash: entry.hash, timestamp: 1000 }
    }),
    push: vi.fn(async (path: string, data: Record<string, unknown>, _baseHash: string | null) => {
      counter += 1
      const hash = `h${counter}`
      store.set(path, { data: data as unknown as Keyring, hash })
      return { hash, timestamp: 2000 }
    }),
  } as unknown as StarfishClient

  return { client, store }
}

// ── keyringPathFor ────────────────────────────────────────────────────────────

describe("keyringPathFor", () => {
  it("returns `<collection>/_keyring`", () => {
    expect(keyringPathFor("myColl")).toBe("myColl/_keyring")
  })
})

// ── currentEpoch ──────────────────────────────────────────────────────────────

describe("currentEpoch", () => {
  it("returns the current epoch from the stored keyring", async () => {
    const admin = makeParty()
    const alice = makeParty()
    const { keyring } = await createKeyring(
      { edPrivHex: admin.edPriv, edPubHex: admin.edPub },
      [{ subKemHex: alice.kemPub }],
    )
    const path = `/pull/${keyringPathFor("vault")}`
    const { client } = makeMockClient({ path, data: keyring, hash: "h0" })

    expect(await currentEpoch(client, "vault")).toBe(1)
  })

  it("returns 0 when no keyring exists yet", async () => {
    const { client } = makeMockClient()
    expect(await currentEpoch(client, "vault")).toBe(0)
  })
})

// ── listRecipients ────────────────────────────────────────────────────────────

describe("listRecipients", () => {
  it("returns recipients of the current epoch with subKem/addedBy/addedAt", async () => {
    const admin = makeParty()
    const alice = makeParty()
    const bob = makeParty()
    const addedAt = 1234567
    const { keyring } = await createKeyring(
      { edPrivHex: admin.edPriv, edPubHex: admin.edPub },
      [{ subKemHex: alice.kemPub }, { subKemHex: bob.kemPub }],
      undefined,
      addedAt,
    )
    const path = `/pull/${keyringPathFor("vault")}`
    const { client } = makeMockClient({ path, data: keyring, hash: "h0" })

    const result = await listRecipients(client, "vault", { trustedAdders: [admin.edPub] })
    expect(result.epoch).toBe(1)
    expect(result.recipients).toHaveLength(2)
    const sorted = [...result.recipients].sort((a, b) => a.subKem.localeCompare(b.subKem))
    const expected = [
      { subKem: alice.kemPub, addedBy: admin.edPub, addedAt },
      { subKem: bob.kemPub, addedBy: admin.edPub, addedAt },
    ].sort((a, b) => a.subKem.localeCompare(b.subKem))
    expect(sorted).toEqual(expected)
  })

  it("returns empty recipients when no keyring exists", async () => {
    const { client } = makeMockClient()
    const result = await listRecipients(client, "vault", { trustedAdders: [makeParty().edPub] })
    expect(result).toEqual({ epoch: 0, recipients: [] })
  })

  it("is fail-closed: throws when trustedAdders is omitted", async () => {
    const admin = makeParty()
    const { keyring } = await createKeyring(
      { edPrivHex: admin.edPriv, edPubHex: admin.edPub },
      [{ subKemHex: makeParty().kemPub }],
    )
    const path = `/pull/${keyringPathFor("vault")}`
    const { client } = makeMockClient({ path, data: keyring, hash: "h0" })
    await expect(listRecipients(client, "vault")).rejects.toThrow(/trustedAdders/)
  })

  it("filters out entries from untrusted adders (hostile-server substitution)", async () => {
    const admin = makeParty() // real owner (genesis adder)
    const attacker = makeParty()
    const alice = makeParty()
    const ghost = makeParty()
    // alice added by the owner; ghost merged in by an attacker (addedBy = attacker).
    const { keyring, cek } = await createKeyring(
      { edPrivHex: admin.edPriv, edPubHex: admin.edPub },
      [{ subKemHex: alice.kemPub }],
    )
    const tampered = await addRecipient(
      keyring,
      { edPrivHex: attacker.edPriv, edPubHex: attacker.edPub },
      cek,
      ghost.kemPub,
    )
    const path = `/pull/${keyringPathFor("vault")}`
    const { client } = makeMockClient({ path, data: tampered, hash: "h0" })

    const result = await listRecipients(client, "vault", { trustedAdders: [admin.edPub] })
    const kems = result.recipients.map((r) => r.subKem)
    expect(kems).toContain(alice.kemPub) // owner-added survives
    expect(kems).not.toContain(ghost.kemPub) // attacker-added filtered out
  })
})

// ── addRecipient ──────────────────────────────────────────────────────────────

describe("addRecipient (collection-scoped)", () => {
  it("adds a new recipient to the current epoch; new recipient can unwrap CEK", async () => {
    const admin = makeParty()
    const alice = makeParty()
    const charlie = makeParty()
    const { keyring, cek } = await createKeyring(
      { edPrivHex: admin.edPriv, edPubHex: admin.edPub },
      [{ subKemHex: admin.kemPub }, { subKemHex: alice.kemPub }],
    )
    const path = `/pull/${keyringPathFor("vault")}`
    const pushPath = `/push/${keyringPathFor("vault")}`
    const { client, store } = makeMockClient({ path, data: keyring, hash: "h0" })

    await addRecipientToCollection(
      client,
      "vault",
      { subKem: charlie.kemPub, userId: "charlie" },
      { edPriv: admin.edPriv, edPub: admin.edPub, kemPriv: admin.kemPriv },
      { trustedAdders: [admin.edPub] },
    )

    // The keyring should now include charlie's entry in epoch 1
    const stored = store.get(pushPath)!.data
    expect(stored.currentEpoch).toBe(1)
    const charlieEntry = stored.epochs["1"].wrappedKeys.find((e) => e.subKem === charlie.kemPub)
    expect(charlieEntry).toBeDefined()

    // Charlie can unwrap and recover the SAME CEK
    const recoveredCek = await unwrapFromEntry(charlieEntry!, charlie.kemPriv)
    expect(bytesToHex(recoveredCek)).toBe(bytesToHex(cek))
  })

  it("a secp256k1 owner grants a secp256k1 member access; member unwraps the shared CEK", async () => {
    // End-to-end through the HTTP layer: the secp owner recovers the current CEK
    // from its own secp entry (recoverCurrentCek → verify + unwrap under secp),
    // then wraps it for a secp member and pushes.
    const owner = makeSecpParty()
    const member = makeSecpParty()
    const { keyring, cek } = await createKeyring(
      { edPrivHex: owner.edPriv, edPubHex: owner.edPub, alg: "secp256k1-schnorr" },
      [{ subKemHex: owner.kemPub, kemAlg: "secp256k1-schnorr" }],
    )
    const path = `/pull/${keyringPathFor("vault")}`
    const pushPath = `/push/${keyringPathFor("vault")}`
    const { client, store } = makeMockClient({ path, data: keyring, hash: "h0" })

    await addRecipientToCollection(
      client,
      "vault",
      { subKem: member.kemPub, kemAlg: "secp256k1-schnorr", userId: "nostr-member" },
      { edPriv: owner.edPriv, edPub: owner.edPub, kemPriv: owner.kemPriv, alg: "secp256k1-schnorr" },
      { trustedAdders: [owner.edPub] },
    )

    const stored = store.get(pushPath)!.data
    const memberEntry = stored.epochs["1"].wrappedKeys.find((e) => e.subKem === member.kemPub)
    expect(memberEntry).toBeDefined()
    expect(memberEntry!.kemAlg).toBe("secp256k1-schnorr")
    const recovered = await unwrapFromEntry(memberEntry!, member.kemPriv)
    expect(bytesToHex(recovered)).toBe(bytesToHex(cek))
  })

  it("preserves existing recipients", async () => {
    const admin = makeParty()
    const alice = makeParty()
    const charlie = makeParty()
    const { keyring } = await createKeyring(
      { edPrivHex: admin.edPriv, edPubHex: admin.edPub },
      [{ subKemHex: admin.kemPub }, { subKemHex: alice.kemPub }],
    )
    const path = `/pull/${keyringPathFor("vault")}`
    const pushPath = `/push/${keyringPathFor("vault")}`
    const { client, store } = makeMockClient({ path, data: keyring, hash: "h0" })

    await addRecipientToCollection(
      client,
      "vault",
      { subKem: charlie.kemPub },
      { edPriv: admin.edPriv, edPub: admin.edPub, kemPriv: admin.kemPriv },
      { trustedAdders: [admin.edPub] },
    )

    const stored = store.get(pushPath)!.data
    const subs = stored.epochs["1"].wrappedKeys.map((e) => e.subKem).sort()
    expect(subs).toEqual([admin.kemPub, alice.kemPub, charlie.kemPub].sort())
  })

  it("passes the previous hash to push for conflict detection", async () => {
    const admin = makeParty()
    const alice = makeParty()
    const charlie = makeParty()
    const { keyring } = await createKeyring(
      { edPrivHex: admin.edPriv, edPubHex: admin.edPub },
      [{ subKemHex: admin.kemPub }, { subKemHex: alice.kemPub }],
    )
    const path = `/pull/${keyringPathFor("vault")}`
    const { client } = makeMockClient({ path, data: keyring, hash: "h-prev" })

    await addRecipientToCollection(
      client,
      "vault",
      { subKem: charlie.kemPub },
      { edPriv: admin.edPriv, edPub: admin.edPub, kemPriv: admin.kemPriv },
      { trustedAdders: [admin.edPub] },
    )

    const pushCalls = (client.push as unknown as { mock: { calls: unknown[][] } }).mock.calls
    expect(pushCalls).toHaveLength(1)
    const [, , baseHash] = pushCalls[0] as [string, Record<string, unknown>, string | null]
    expect(baseHash).toBe("h-prev")
  })

  it("throws when keyring document does not exist", async () => {
    const admin = makeParty()
    const charlie = makeParty()
    const { client } = makeMockClient()
    await expect(
      addRecipientToCollection(
        client,
        "vault",
        { subKem: charlie.kemPub },
        { edPriv: admin.edPriv, edPub: admin.edPub, kemPriv: admin.kemPriv },
      ),
    ).rejects.toThrow()
  })

  // A hostile server can REPLACE the adder's own entry with one wrapping an
  // attacker-chosen CEK to the adder's (public) KEM key, self-signed by an
  // attacker ed key. Every field is derivable from public material, and the
  // self-attesting addedSig verifies, so without a trustedAdders pin the adder
  // unwraps the forged CEK and re-wraps it for the new recipient.
  async function forgeReplacedAdminEntry(admin: TestParty, attacker: TestParty) {
    const { keyring } = await createKeyring(
      { edPrivHex: admin.edPriv, edPubHex: admin.edPub },
      [{ subKemHex: admin.kemPub }],
    )
    const attackerCek = new Uint8Array(32).fill(0xab)
    const forged = await wrapForRecipient(attackerCek, admin.kemPub, {
      adderEdPrivHex: attacker.edPriv,
      adderEdPubHex: attacker.edPub,
      addedAt: 1,
      epoch: 1,
    })
    keyring.epochs["1"]!.wrappedKeys = [forged]
    return { keyring, attackerCek }
  }

  it("with trustedAdders, rejects a server-replaced entry signed by an untrusted adder", async () => {
    const admin = makeParty()
    const attacker = makeParty()
    const charlie = makeParty()
    const { keyring } = await forgeReplacedAdminEntry(admin, attacker)
    const path = `/pull/${keyringPathFor("vault")}`
    const { client } = makeMockClient({ path, data: keyring, hash: "h0" })

    await expect(
      addRecipientToCollection(
        client,
        "vault",
        { subKem: charlie.kemPub },
        { edPriv: admin.edPriv, edPub: admin.edPub, kemPriv: admin.kemPriv },
        { trustedAdders: [admin.edPub] },
      ),
    ).rejects.toThrow()
  })

  it("fails closed: addRecipient throws when trustedAdders is omitted", async () => {
    // Previously, omitting trustedAdders silently accepted a server-replaced
    // entry and re-wrapped the attacker's CEK for the newcomer. The mutation
    // helpers now refuse to run without a provenance pin.
    const admin = makeParty()
    const charlie = makeParty()
    const { keyring } = await createKeyring(
      { edPrivHex: admin.edPriv, edPubHex: admin.edPub },
      [{ subKemHex: admin.kemPub }],
    )
    const path = `/pull/${keyringPathFor("vault")}`
    const { client } = makeMockClient({ path, data: keyring, hash: "h0" })

    await expect(
      addRecipientToCollection(
        client,
        "vault",
        { subKem: charlie.kemPub },
        { edPriv: admin.edPriv, edPub: admin.edPub, kemPriv: admin.kemPriv },
      ),
    ).rejects.toThrow(/trustedAdders/)
  })

  it("fails closed on a duplicate subKem in the current epoch (tampering)", async () => {
    // A valid epoch has unique subKems. Two entries for the same subKem mean the
    // keyring was tampered with (e.g. a hostile server injected a second entry
    // wrapping an attacker-chosen CEK to the adder's own key, self-signed by the
    // adder's key so it survives the trustedAdders + addedSig checks).
    // recoverCurrentCek must fail closed on the duplicate rather than probe past
    // it. Mirrors the Python twin in test_recipients.py.
    const admin = makeParty()
    const charlie = makeParty()
    const { keyring, cek } = await createKeyring(
      { edPrivHex: admin.edPriv, edPubHex: admin.edPub },
      [{ subKemHex: admin.kemPub }],
    )
    const duplicate = await wrapForRecipient(cek, admin.kemPub, {
      adderEdPrivHex: admin.edPriv,
      adderEdPubHex: admin.edPub,
      addedAt: 2,
      epoch: 1,
    })
    keyring.epochs["1"]!.wrappedKeys.push(duplicate)
    const path = `/pull/${keyringPathFor("vault")}`
    const { client } = makeMockClient({ path, data: keyring, hash: "h0" })

    await expect(
      addRecipientToCollection(
        client,
        "vault",
        { subKem: charlie.kemPub },
        { edPriv: admin.edPriv, edPub: admin.edPub, kemPriv: admin.kemPriv },
        { trustedAdders: [admin.edPub] },
      ),
    ).rejects.toThrow(/duplicate/)
  })
})

// ── removeRecipient ──────────────────────────────────────────────────────────

describe("removeRecipient (collection-scoped)", () => {
  it("increments epoch by 1 and excludes removed recipients", async () => {
    const admin = makeParty()
    const alice = makeParty()
    const bob = makeParty()
    const { keyring } = await createKeyring(
      { edPrivHex: admin.edPriv, edPubHex: admin.edPub },
      [{ subKemHex: admin.kemPub }, { subKemHex: alice.kemPub }, { subKemHex: bob.kemPub }],
    )
    const path = `/pull/${keyringPathFor("vault")}`
    const pushPath = `/push/${keyringPathFor("vault")}`
    const { client, store } = makeMockClient({ path, data: keyring, hash: "h0" })

    const result = await removeRecipient(
      client,
      "vault",
      [bob.kemPub],
      { edPriv: admin.edPriv, edPub: admin.edPub, kemPriv: admin.kemPriv },
      { trustedAdders: [admin.edPub] },
    )

    expect(result.newEpoch).toBe(2)

    const stored = store.get(pushPath)!.data
    expect(stored.currentEpoch).toBe(2)
    const epoch2Subs = stored.epochs["2"].wrappedKeys.map((e) => e.subKem)
    expect(epoch2Subs).toContain(admin.kemPub)
    expect(epoch2Subs).toContain(alice.kemPub)
    expect(epoch2Subs).not.toContain(bob.kemPub)
  })

  it("retained recipients can still unwrap the new epoch's CEK", async () => {
    const admin = makeParty()
    const alice = makeParty()
    const bob = makeParty()
    const { keyring } = await createKeyring(
      { edPrivHex: admin.edPriv, edPubHex: admin.edPub },
      [{ subKemHex: admin.kemPub }, { subKemHex: alice.kemPub }, { subKemHex: bob.kemPub }],
    )
    const path = `/pull/${keyringPathFor("vault")}`
    const pushPath = `/push/${keyringPathFor("vault")}`
    const { client, store } = makeMockClient({ path, data: keyring, hash: "h0" })

    await removeRecipient(
      client,
      "vault",
      [bob.kemPub],
      { edPriv: admin.edPriv, edPub: admin.edPub, kemPriv: admin.kemPriv },
      { trustedAdders: [admin.edPub] },
    )

    const stored = store.get(pushPath)!.data
    const aliceEntry = stored.epochs["2"].wrappedKeys.find((e) => e.subKem === alice.kemPub)
    expect(aliceEntry).toBeDefined()
    const newCek = await unwrapFromEntry(aliceEntry!, alice.kemPriv)
    expect(newCek.byteLength).toBe(32)

    // Bob (removed) has no entry in epoch 2.
    expect(stored.epochs["2"].wrappedKeys.find((e) => e.subKem === bob.kemPub)).toBeUndefined()
  })

  it("throws when keyring does not exist", async () => {
    const admin = makeParty()
    const bob = makeParty()
    const { client } = makeMockClient()
    await expect(
      removeRecipient(
        client,
        "vault",
        [bob.kemPub],
        { edPriv: admin.edPriv, edPub: admin.edPub, kemPriv: admin.kemPriv },
      ),
    ).rejects.toThrow()
  })

  it("does NOT re-wrap the fresh CEK to a tampered retained entry (laundering guard)", async () => {
    // A hostile server swaps a retained entry's `subKem` to an attacker key,
    // leaving `addedBy` = a trusted adder. The `addedSig` was computed over the
    // original subKem, so it no longer verifies. A rotation that only checked
    // `addedBy` (the old behavior) would re-wrap the fresh CEK to the attacker —
    // laundering a forged recipient into a legitimately signed new-epoch entry.
    // The rotation must verify `addedSig` and drop the entry. Mirrors the
    // Python twin in test_recipients.py.
    const admin = makeParty()
    const alice = makeParty()
    const attacker = makeParty()
    const { keyring } = await createKeyring(
      { edPrivHex: admin.edPriv, edPubHex: admin.edPub },
      [{ subKemHex: admin.kemPub }, { subKemHex: alice.kemPub }],
    )
    const aliceEntry = keyring.epochs["1"]!.wrappedKeys.find((e) => e.subKem === alice.kemPub)!
    aliceEntry.subKem = attacker.kemPub // addedBy stays admin (trusted); addedSig now invalid

    const path = `/pull/${keyringPathFor("vault")}`
    const pushPath = `/push/${keyringPathFor("vault")}`
    const { client, store } = makeMockClient({ path, data: keyring, hash: "h0" })

    // Rotate (remove nobody). The tampered subKem must not survive.
    await removeRecipient(
      client,
      "vault",
      [],
      { edPriv: admin.edPriv, edPub: admin.edPub, kemPriv: admin.kemPriv },
      { trustedAdders: [admin.edPub] },
    )

    const stored = store.get(pushPath)!.data
    const epoch2Subs = stored.epochs["2"].wrappedKeys.map((e) => e.subKem)
    expect(epoch2Subs).not.toContain(attacker.kemPub) // forged recipient not laundered in
    expect(epoch2Subs).toContain(admin.kemPub) // untampered entry still survives
  })
})
