/**
 * v3.0 author-signature plumbing — `SyncManager` with a `signer`.
 *
 * When a `signer` is configured, push payloads must carry:
 *   - `authorPubkey`: the dev Ed25519 pub (hex)
 *   - `authorSignature`: base64 Ed25519 over `stableStringify(payload-without-author-fields)`
 *
 * The signature is over the canonical stringification of the entire encrypted
 * payload (e.g. `{_encrypted, _epoch}`), *not* the plaintext.
 */
import { describe, it, expect, vi } from "vitest"
import { ed25519 } from "@noble/curves/ed25519.js"
import { stableStringify } from "@drakkar.software/starfish-protocol"
import { StarfishClient } from "@drakkar.software/starfish-client"
import { SyncManager } from "@drakkar.software/starfish-client"
import type { SyncSigner } from "@drakkar.software/starfish-client"
import { deriveRootIdentity } from "../src/identity.js"
import { createKeyring, createKeyringEncryptor } from "@drakkar.software/starfish-keyring"
import type { PullResult, PushSuccess } from "@drakkar.software/starfish-protocol"

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}
function b64decode(s: string): Uint8Array {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
}

function mockClient(overrides: {
  pull?: (path: string, checkpoint?: number) => Promise<PullResult>
  push?: (
    path: string,
    data: Record<string, unknown>,
    baseHash: string | null,
  ) => Promise<PushSuccess>
} = {}) {
  return {
    pull: overrides.pull ?? vi.fn(async () => ({
      data: { key: "value" },
      hash: "h",
      timestamp: 1,
    })),
    push: overrides.push ?? vi.fn(async () => ({ hash: "h2", timestamp: 2 })),
  } as unknown as StarfishClient
}

async function makeSignerFor(devEdPrivHex: string, devEdPubHex: string): Promise<SyncSigner> {
  const priv = hexToBytes(devEdPrivHex)
  return {
    getSigner: async () => ({
      devEdPubHex,
      sign: async (payload: Uint8Array) => ed25519.sign(payload, priv),
    }),
  }
}

describe("SyncManager author-signature with KeyringEncryptor + signer", () => {
  it("push attaches authorPubkey + authorSignature to the encrypted payload", async () => {
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const laptop = await deriveRootIdentity("alice-laptop")
    const { keyring } = await createKeyring(
      { edPrivHex: alice.keys.edPriv, edPubHex: alice.keys.edPub },
      [{ subKemHex: laptop.keys.kemPub }],
    )
    const encryptor = await createKeyringEncryptor(
      keyring,
      { kemPubHex: laptop.keys.kemPub, kemPrivHex: laptop.keys.kemPriv },
      { trustedAdders: [alice.keys.edPub] },
    )

    const pushFn = vi.fn(async () => ({ hash: "h2", timestamp: 2 }))
    const client = mockClient({ push: pushFn as never })

    const signer = await makeSignerFor(laptop.keys.edPriv, laptop.keys.edPub)
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      encryptor,
      signer,
    })

    await sync.push({ secret: "x" })

    expect(pushFn).toHaveBeenCalledTimes(1)
    const [, payload] = pushFn.mock.calls[0] as [
      string,
      Record<string, unknown>,
      string | null,
    ]
    expect(payload).toHaveProperty("_encrypted")
    expect(payload).toHaveProperty("_epoch")
    expect(payload.authorPubkey).toBe(laptop.keys.edPub)
    const authorSignature = payload.authorSignature as string
    expect(typeof authorSignature).toBe("string")
    expect(authorSignature.length).toBeGreaterThan(0)

    // Independently verify: the signed bytes are stableStringify(payload-without-author-fields).
    // SyncManager signs before attaching author fields, so the canonical input is
    // stableStringify of the sealed payload (e.g. {_encrypted, _epoch}).
    const signedObj: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(payload)) {
      if (k === "authorPubkey" || k === "authorSignature") continue
      signedObj[k] = v
    }
    const message = new TextEncoder().encode(stableStringify(signedObj))
    const sigBytes = b64decode(authorSignature)
    const ok = ed25519.verify(sigBytes, message, hexToBytes(laptop.keys.edPub))
    expect(ok).toBe(true)
  })

  it("does not attach author fields when signer is not configured", async () => {
    const pushFn = vi.fn(async () => ({ hash: "h", timestamp: 1 }))
    const client = mockClient({ push: pushFn as never })
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })
    await sync.push({ a: 1 })
    expect(pushFn).toHaveBeenCalledTimes(1)
    // Three positional args: (path, data, baseHash). No author-signature slot.
    const call = pushFn.mock.calls[0] as unknown[]
    expect(call.length).toBe(3)
  })
})
