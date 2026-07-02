import { describe, it, expect, beforeAll } from "vitest"
import { configurePlatform, ed25519Suite } from "@drakkar.software/starfish-protocol"
import {
  generateSpaceWriteKey,
  sealAad,
  sealDocument,
  openSealedDocument,
  isSealedBlob,
} from "../src/sealed-write.js"

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

// The webhook's own signing identity (the "sealer").
const webhook = ed25519Suite.generateSignerKeypair()
const sealerKeys = { edPubHex: webhook.pubHex, edPrivHex: webhook.privHex }

describe("sealed-write (Option B)", () => {
  it("a keyless writer seals with only the public key; a member opens with the private key", async () => {
    const space = generateSpaceWriteKey()
    const message = { t: "msg", e: { id: "m1", text: "from the webhook", ts: 1 } }

    // The webhook holds only the PUBLIC write key (+ its own signing key).
    const blob = await sealDocument(message, space.kemPubHex, sealerKeys)
    expect(isSealedBlob(blob)).toBe(true)

    // A member holds the PRIVATE write key and recovers the cleartext, pinning the
    // webhook as the required sealer.
    const opened = await openSealedDocument(blob, space.kemPrivHex, webhook.pubHex)
    expect(opened).toEqual(message)
  })

  it("is write-only: the sealed blob carries no readable plaintext", async () => {
    const space = generateSpaceWriteKey()
    const blob = await sealDocument({ secret: "top-secret" }, space.kemPubHex, sealerKeys)
    // The serialized blob must not leak the plaintext anywhere.
    expect(JSON.stringify(blob)).not.toContain("top-secret")
  })

  it("cannot be opened with the wrong private key", async () => {
    const space = generateSpaceWriteKey()
    const other = generateSpaceWriteKey()
    const blob = await sealDocument({ text: "hi" }, space.kemPubHex, sealerKeys)
    await expect(openSealedDocument(blob, other.kemPrivHex, webhook.pubHex)).rejects.toThrow()
  })

  it("pins provenance: requireSealer rejects a blob from a different signer", async () => {
    const space = generateSpaceWriteKey()
    const blob = await sealDocument({ text: "hi" }, space.kemPubHex, sealerKeys)

    // Correct sealer pin opens.
    await expect(
      openSealedDocument(blob, space.kemPrivHex, webhook.pubHex),
    ).resolves.toEqual({ text: "hi" })

    // A different required sealer is rejected.
    const impostor = ed25519Suite.generateSignerKeypair()
    await expect(
      openSealedDocument(blob, space.kemPrivHex, impostor.pubHex),
    ).rejects.toThrow()
  })

  it("mandatory sealer pin: a blob sealed by a non-webhook key is rejected", async () => {
    const space = generateSpaceWriteKey()
    // The write PUBLIC key is published, so anyone can seal to it with their OWN
    // signing key — pinning is what tells a genuine webhook message from a forgery.
    const impostor = ed25519Suite.generateSignerKeypair()
    const forged = await sealDocument({ text: "forged" }, space.kemPubHex, {
      edPubHex: impostor.pubHex,
      edPrivHex: impostor.privHex,
    })
    await expect(
      openSealedDocument(forged, space.kemPrivHex, webhook.pubHex),
    ).rejects.toThrow()

    // A genuine webhook-sealed blob opens under the same pin.
    const genuine = await sealDocument({ text: "genuine" }, space.kemPubHex, sealerKeys)
    await expect(
      openSealedDocument(genuine, space.kemPrivHex, webhook.pubHex),
    ).resolves.toEqual({ text: "genuine" })
  })

  it("binds to a context via aad: a blob sealed for context A cannot be opened under context B", async () => {
    const space = generateSpaceWriteKey()
    const aadA = sealAad("events/roomA", "hook1")
    const aadB = sealAad("events/roomB", "hook1")
    const blob = await sealDocument({ text: "hi" }, space.kemPubHex, sealerKeys, aadA)

    // Relocation to a different context is rejected.
    await expect(
      openSealedDocument(blob, space.kemPrivHex, webhook.pubHex, { aad: aadB }),
    ).rejects.toThrow()

    // A no-aad open of a context-bound (v:1) blob is rejected (downgrade guard).
    await expect(
      openSealedDocument(blob, space.kemPrivHex, webhook.pubHex),
    ).rejects.toThrow()

    // The matching context opens.
    await expect(
      openSealedDocument(blob, space.kemPrivHex, webhook.pubHex, { aad: aadA }),
    ).resolves.toEqual({ text: "hi" })
  })

  it("isSealedBlob distinguishes sealed from plaintext documents", () => {
    expect(isSealedBlob({ t: "msg", e: {} })).toBe(false)
    expect(isSealedBlob(null)).toBe(false)
    expect(isSealedBlob("string")).toBe(false)
  })
})
