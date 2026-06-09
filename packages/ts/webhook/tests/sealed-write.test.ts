import { describe, it, expect, beforeAll } from "vitest"
import { configurePlatform, ed25519Suite } from "@drakkar.software/starfish-protocol"
import {
  generateSpaceWriteKey,
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

    // A member holds the PRIVATE write key and recovers the cleartext.
    const opened = await openSealedDocument(blob, space.kemPrivHex)
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
    await expect(openSealedDocument(blob, other.kemPrivHex)).rejects.toThrow()
  })

  it("pins provenance: requireSealer rejects a blob from a different signer", async () => {
    const space = generateSpaceWriteKey()
    const blob = await sealDocument({ text: "hi" }, space.kemPubHex, sealerKeys)

    // Correct sealer pin opens.
    await expect(
      openSealedDocument(blob, space.kemPrivHex, { requireSealer: webhook.pubHex }),
    ).resolves.toEqual({ text: "hi" })

    // A different required sealer is rejected.
    const impostor = ed25519Suite.generateSignerKeypair()
    await expect(
      openSealedDocument(blob, space.kemPrivHex, { requireSealer: impostor.pubHex }),
    ).rejects.toThrow()
  })

  it("isSealedBlob distinguishes sealed from plaintext documents", () => {
    expect(isSealedBlob({ t: "msg", e: {} })).toBe(false)
    expect(isSealedBlob(null)).toBe(false)
    expect(isSealedBlob("string")).toBe(false)
  })
})
