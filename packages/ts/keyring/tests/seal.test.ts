/**
 * Sealed-envelope round-trips: self-seal, peer-seal, sealer pinning, and the
 * wrong-recipient / tamper failure modes that make trial-unseal safe.
 */
import { describe, it, expect, beforeAll } from "vitest"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { ed25519, x25519 } from "@noble/curves/ed25519.js"

import { seal, sealToSelf, unseal, unsealToString, unsealFromSelf } from "../src/seal.js"

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

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
}

/** A fresh identity: Ed25519 signing keypair + X25519 KEM keypair (all hex). */
function makeIdentity() {
  const edPriv = ed25519.utils.randomSecretKey()
  const kemPriv = x25519.utils.randomSecretKey()
  return {
    edPrivHex: hex(edPriv),
    edPubHex: hex(ed25519.getPublicKey(edPriv)),
    kemPrivHex: hex(kemPriv),
    kemPubHex: hex(x25519.getPublicKey(kemPriv)),
  }
}

describe("sealed envelopes", () => {
  it("self-seal round-trips a string for the same account", async () => {
    const me = makeIdentity()
    const blob = await sealToSelf("bearer-secret-123", me.kemPubHex, me)
    expect(await unsealToString(blob, me.kemPrivHex)).toBe("bearer-secret-123")
    // The convenience self-open (sealer pinned to our own Ed key) also works.
    const out = await unsealFromSelf(blob, { kemPrivHex: me.kemPrivHex, edPubHex: me.edPubHex })
    expect(new TextDecoder().decode(out)).toBe("bearer-secret-123")
  })

  it("seals raw bytes to a peer that only the peer can open", async () => {
    const sender = makeIdentity()
    const peer = makeIdentity()
    const payload = new Uint8Array([1, 2, 3, 4, 250, 251, 252])
    const blob = await seal(payload, peer.kemPubHex, sender)
    expect(blob.entry.addedBy).toBe(sender.edPubHex)
    expect(Array.from(await unseal(blob, peer.kemPrivHex))).toEqual(Array.from(payload))
  })

  it("rejects a wrong recipient (the trial-unseal failure mode)", async () => {
    const sender = makeIdentity()
    const peer = makeIdentity()
    const stranger = makeIdentity()
    const blob = await seal("for-peer-only", peer.kemPubHex, sender)
    await expect(unseal(blob, stranger.kemPrivHex)).rejects.toThrow()
  })

  it("enforces requireSealer when pinning the sender", async () => {
    const sender = makeIdentity()
    const impostor = makeIdentity()
    const peer = makeIdentity()
    const blob = await seal("hi", peer.kemPubHex, sender)
    expect(await unsealToString(blob, peer.kemPrivHex, { requireSealer: sender.edPubHex })).toBe("hi")
    await expect(unseal(blob, peer.kemPrivHex, { requireSealer: impostor.edPubHex })).rejects.toThrow()
  })

  it("rejects a tampered ciphertext", async () => {
    const me = makeIdentity()
    const blob = await sealToSelf("integrity", me.kemPubHex, me)
    const tampered = { ...blob, ct: blob.ct.slice(0, -4) + (blob.ct.endsWith("AAAA") ? "BBBB" : "AAAA") }
    await expect(unseal(tampered, me.kemPrivHex)).rejects.toThrow()
  })
})

// ── AAD context-binding (v:1) ─────────────────────────────────────────────────

describe("sealed envelopes — AAD context-binding (v:1)", () => {
  it("seal with aad sets v:1 on the blob", async () => {
    const me = makeIdentity()
    const blob = await sealToSelf("secret", me.kemPubHex, me, "spaces/sp-abc")
    expect(blob.v).toBe(1)
  })

  it("seal without aad does NOT set v (backward-compatible)", async () => {
    const me = makeIdentity()
    const blob = await sealToSelf("secret", me.kemPubHex, me)
    expect(blob.v).toBeUndefined()
  })

  it("round-trips with aad through sealToSelf / unsealFromSelf", async () => {
    const me = makeIdentity()
    const aad = "spaces/sp-abc/context"
    const blob = await sealToSelf("my-secret", me.kemPubHex, me, aad)
    const raw = await unsealFromSelf(blob, { kemPrivHex: me.kemPrivHex, edPubHex: me.edPubHex }, { aad })
    expect(new TextDecoder().decode(raw)).toBe("my-secret")
  })

  it("round-trips with aad through seal / unseal (peer)", async () => {
    const sender = makeIdentity()
    const peer = makeIdentity()
    const aad = "collection-id:coll-42"
    const blob = await seal("peer-secret", peer.kemPubHex, sender, aad)
    expect(blob.v).toBe(1)
    const out = await unseal(blob, peer.kemPrivHex, { aad })
    expect(new TextDecoder().decode(out)).toBe("peer-secret")
  })

  it("round-trips with aad through seal / unsealToString", async () => {
    const me = makeIdentity()
    const blob = await seal("text-secret", me.kemPubHex, me, "my-context")
    const text = await unsealToString(blob, me.kemPrivHex, { aad: "my-context" })
    expect(text).toBe("text-secret")
  })

  it("v:1 blob WITHOUT aad on open throws immediately (downgrade guard)", async () => {
    const me = makeIdentity()
    const blob = await sealToSelf("guarded", me.kemPubHex, me, "spaces/sp-abc")
    expect(blob.v).toBe(1)
    await expect(unseal(blob, me.kemPrivHex)).rejects.toThrow(/aad required/)
    await expect(unsealFromSelf(blob, { kemPrivHex: me.kemPrivHex, edPubHex: me.edPubHex })).rejects.toThrow(
      /aad required/,
    )
  })

  it("v:1 blob with WRONG aad fails at AEAD authentication", async () => {
    const me = makeIdentity()
    const blob = await sealToSelf("aad-locked", me.kemPubHex, me, "correct-context")
    await expect(unseal(blob, me.kemPrivHex, { aad: "wrong-context" })).rejects.toThrow()
  })

  it("legacy (no v) blob opens fine without aad", async () => {
    const me = makeIdentity()
    // Simulate a legacy blob with no v field.
    const legacyBlob = await sealToSelf("legacy", me.kemPubHex, me)
    expect(legacyBlob.v).toBeUndefined()
    const text = await unsealToString(legacyBlob, me.kemPrivHex)
    expect(text).toBe("legacy")
  })

  it("legacy blob with v:1 stripped does not bypass aad (auth tag mismatch)", async () => {
    // Adversary strips v:1 to bypass the guard. The AEAD auth tag covers aad,
    // so the ciphertext is still authenticated — opening WITHOUT aad fails.
    const me = makeIdentity()
    const blob = await sealToSelf("guarded-data", me.kemPubHex, me, "ctx")
    // Strip v:1 from the blob to simulate attacker manipulation.
    const strippedBlob = { entry: blob.entry, ct: blob.ct } // no v
    // Opening without aad (the blob has no v, so guard doesn't fire) but the
    // AEAD auth tag still covers aad bytes, so decryption MUST fail.
    await expect(unseal(strippedBlob, me.kemPrivHex)).rejects.toThrow()
  })
})
