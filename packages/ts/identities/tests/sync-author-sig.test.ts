/**
 * v3.0 document author-proof plumbing — `SyncManager` with a `signer`.
 *
 * When a `signer` is configured, the push carries the author proof as a 4th
 * argument to `client.push` (top-level body siblings of `data`, NOT inside it):
 *   - `authorPubkey`: the dev Ed25519 pub (hex)
 *   - `authorSignature`: base64 Ed25519 over the doc-author canonical input —
 *     `DOC_AUTHOR_DOMAIN + stableStringify({k: documentKey, d: sealed})`.
 *
 * The signature is over the canonical form of the encrypted payload (e.g.
 * `{_encrypted, _epoch}`) bound to the documentKey, *not* the plaintext.
 */
import { describe, it, expect, vi } from "vitest"
import { ed25519 } from "@noble/curves/ed25519.js"
import { verifyDocAuthor, type AppendAuthor } from "@drakkar.software/starfish-protocol"
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

function mockClient(overrides: {
  pull?: (path: string, checkpoint?: number) => Promise<PullResult>
  push?: (
    path: string,
    data: Record<string, unknown>,
    baseHash: string | null,
    author?: AppendAuthor,
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

describe("SyncManager document author-proof with KeyringEncryptor + signer", () => {
  it("push passes a verifiable author proof as the 4th arg (top-level, not in data)", async () => {
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
      pullPath: "/pull/notes",
      pushPath: "/push/notes",
      encryptor,
      signer,
    })

    await sync.push({ secret: "x" })

    expect(pushFn).toHaveBeenCalledTimes(1)
    const [, payload, , author] = pushFn.mock.calls[0] as [
      string,
      Record<string, unknown>,
      string | null,
      AppendAuthor | undefined,
    ]
    // The encrypted payload is sent as `data`, WITHOUT author fields (those are
    // now the top-level 4th arg).
    expect(payload).toHaveProperty("_encrypted")
    expect(payload).toHaveProperty("_epoch")
    expect(payload.authorPubkey).toBeUndefined()
    expect(payload.authorSignature).toBeUndefined()

    expect(author).toBeDefined()
    expect(author!.authorPubkey).toBe(laptop.keys.edPub)
    // The proof verifies as a DOCUMENT author signature over the sealed payload,
    // bound to the documentKey ("notes", derived from "/push/notes").
    expect(
      verifyDocAuthor("notes", payload, author!.authorPubkey, author!.authorSignature, "ed25519"),
    ).toBe(true)
    // …and NOT under a different documentKey (path binding).
    expect(
      verifyDocAuthor("other", payload, author!.authorPubkey, author!.authorSignature, "ed25519"),
    ).toBe(false)
  })

  it("passes no author proof when a signer is not configured", async () => {
    const pushFn = vi.fn(async () => ({ hash: "h", timestamp: 1 }))
    const client = mockClient({ push: pushFn as never })
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })
    await sync.push({ a: 1 })
    expect(pushFn).toHaveBeenCalledTimes(1)
    const [, data, , author] = pushFn.mock.calls[0] as unknown[]
    // The 4th positional arg (author proof) is undefined; `data` carries no author fields.
    expect(author).toBeUndefined()
    expect((data as Record<string, unknown>).authorPubkey).toBeUndefined()
  })
})
