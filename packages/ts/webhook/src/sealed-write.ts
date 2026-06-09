/**
 * Sealed-write (Option B): let a KEYLESS external writer encrypt a message into an
 * end-to-end-encrypted space using only a PUBLISHED public key.
 *
 * The asymmetry is the whole point. Starfish's `delegated` mode encrypts content
 * with a shared symmetric CEK that every reader also holds — so to WRITE you must
 * be able to READ. A webhook should be able to inject a message but never decrypt
 * the history. This builds that "write-only" party on the keyring's existing
 * anonymous-sender primitive (`seal`/`unseal`, ephemeral X25519 → HKDF → AES-GCM):
 *
 *   1. A space declares a write keypair via {@link generateSpaceWriteKey}.
 *      The PUBLIC half is published openly (any plaintext doc); the PRIVATE half is
 *      distributed to members out of band (e.g. wrapped into the space keyring).
 *   2. The webhook seals each message to the public half ({@link sealDocument}) and
 *      stores the resulting blob in an ordinary `none`/plaintext collection. The
 *      server only ever holds ciphertext — true E2EE from the webhook edge onward.
 *   3. Members open it with the private half ({@link openSealedDocument}), pinning
 *      the webhook's signing key as the required sealer for provenance.
 *
 * The webhook holds the public write key and its own signing key; it can encrypt
 * to the space but cannot read anything sealed by anyone else.
 */

import { seal, unseal, type SealedBlob, type SealerKeys } from "@drakkar.software/starfish-keyring"
import { ed25519Suite } from "@drakkar.software/starfish-protocol"

export type { SealedBlob, SealerKeys }

/** A space write keypair. Writers seal to {@link kemPubHex}; only holders of
 *  {@link kemPrivHex} (members) can open. The private half is distributed to
 *  members out of band — this function only mints the pair. */
export interface SpaceWriteKey {
  /** X25519 public key (hex) — published openly; webhooks seal to it. */
  kemPubHex: string
  /** X25519 private key (hex) — distributed to readers; opens sealed messages. */
  kemPrivHex: string
}

/** Mint a fresh space write keypair (X25519). */
export function generateSpaceWriteKey(): SpaceWriteKey {
  const { pubHex, privHex } = ed25519Suite.generateKemKeypair()
  return { kemPubHex: pubHex, kemPrivHex: privHex }
}

/**
 * Seal a JSON document to a space write public key, signed by `sealer`. The result
 * is a plain JSON object (`{ entry, ct }`) safe to store in a `none` collection.
 */
export async function sealDocument(
  data: Record<string, unknown>,
  recipientKemPubHex: string,
  sealer: SealerKeys,
): Promise<SealedBlob> {
  return seal(JSON.stringify(data), recipientKemPubHex, sealer)
}

/**
 * Open a {@link sealDocument} blob with the space write PRIVATE key, returning the
 * parsed JSON. Pass `opts.requireSealer` (the webhook's Ed25519 pubkey hex) to pin
 * provenance — the open then throws unless the blob was sealed by that key.
 */
export async function openSealedDocument(
  blob: SealedBlob,
  recipientKemPrivHex: string,
  opts: { requireSealer?: string } = {},
): Promise<Record<string, unknown>> {
  const bytes = await unseal(blob, recipientKemPrivHex, opts)
  return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>
}

/** Structural check that `value` is a {@link SealedBlob} — lets a reader detect a
 *  sealed element when a log mixes sealed and plaintext writes. */
export function isSealedBlob(value: unknown): value is SealedBlob {
  return (
    typeof value === "object" &&
    value !== null &&
    "entry" in value &&
    "ct" in value &&
    typeof (value as { ct: unknown }).ct === "string"
  )
}
