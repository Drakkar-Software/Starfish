/**
 * Generic client-side blob sealing helpers.
 *
 * Provides a structural {@link ByteSealer} interface and two convenience
 * functions — {@link sealAndPushBlob} / {@link pullAndOpenBlob} — that wire a
 * sealer (e.g. a `KeyringEncryptor` from `@drakkar.software/starfish-keyring`)
 * into the binary blob transport (`StarfishClient.pushBlob` / `pullBlob`).
 *
 * The server collection must use `encryption: "none"` — all sealing and
 * unsealing happens client-side. The server stores and returns opaque
 * ciphertext.
 *
 * **AAD (Additional Authenticated Data):** callers MUST pass a stable, unique
 * `aad` string (typically the storage path, e.g. the value returned by a
 * `*Name(spaceId, blobId)` helper). The AAD is bound into the AES-GCM tag
 * and prevents ciphertext relocation: a blob sealed with AAD `"path/a"` cannot
 * be opened as `"path/b"`. When `aad` is omitted, the document key (path with
 * the `/push/` or `/pull/` action prefix stripped) is used as a fallback —
 * the same key is derived on both the seal and open side so round-trips work
 * without an explicit `aad`. **Callers with existing sealed data MUST pass the
 * same explicit AAD they used when sealing** to preserve back-compat.
 *
 * @module blob-seal
 */

import type { StarfishClient } from "./client.js"
import type { BlobPushResult } from "./client.js"

/**
 * Strip the `/push/` or `/pull/` action prefix to derive the bare document
 * key, which is the canonical default AAD for a sealed blob.
 *
 * Both `sealAndPushBlob` (push path) and `pullAndOpenBlob` (pull path) use
 * this so their default AADs agree when the caller omits `aad`.
 */
function documentKey(path: string): string {
  if (path.startsWith("/push/")) return path.slice("/push/".length)
  if (path.startsWith("/pull/")) return path.slice("/pull/".length)
  return path
}

// ---------------------------------------------------------------------------
// ByteSealer
// ---------------------------------------------------------------------------

/**
 * Structural interface satisfied by a `KeyringEncryptor` from
 * `@drakkar.software/starfish-keyring` (and any compatible cipher adapter).
 *
 * Implementations must use AES-256-GCM and bind the `aad` into the ciphertext
 * tag so that relocation is detected on open.
 */
export interface ByteSealer {
  /**
   * Encrypt `bytes` and return the sealed ciphertext.
   * @param bytes - Plaintext bytes to seal.
   * @param aad   - Additional authenticated data bound into the ciphertext tag.
   *                Must be the same string passed to {@link openBytes}.
   */
  sealBytes(bytes: Uint8Array, aad?: string): Promise<Uint8Array>
  /**
   * Decrypt a sealed blob back to plaintext bytes.
   * @param blob - Ciphertext produced by {@link sealBytes}.
   * @param aad  - Same AAD string that was used during sealing.
   * @throws if the ciphertext has been tampered with or the AAD does not match.
   */
  openBytes(blob: Uint8Array, aad?: string): Promise<Uint8Array>
}

// ---------------------------------------------------------------------------
// sealAndPushBlob
// ---------------------------------------------------------------------------

/** Options for {@link sealAndPushBlob}. */
export interface SealAndPushBlobOptions {
  /**
   * Additional authenticated data bound into the AES-GCM ciphertext tag.
   *
   * Callers with existing sealed data MUST pass the **same explicit AAD** they
   * used when originally sealing so that already-stored blobs can still be
   * opened.  When omitted, the document key (push path with the `/push/`
   * prefix stripped) is used as a fallback.
   */
  aad?: string
  /**
   * When set, throws a `RangeError` before sealing if `bytes.length` exceeds
   * this limit.  Checked against the **plaintext** size (before sealing adds
   * overhead).
   *
   * Note: AES-256-GCM sealing adds ~28 bytes of overhead (12-byte nonce +
   * 16-byte tag). If you are mirroring the server's `maxBodyBytes` limit,
   * subtract at least 28 to ensure the sealed ciphertext also fits.
   */
  maxBytes?: number
}

/**
 * Seal `bytes` with `sealer` (AAD bound to the storage path) and push the
 * resulting ciphertext to the server via `client.pushBlob`.
 *
 * Sealed bytes are always pushed with `Content-Type: application/octet-stream`,
 * matching the `allowedMimeTypes` of a {@link createSealedParquetCollection} preset.
 *
 * @param client  - A connected `StarfishClient`.
 * @param sealer  - A `ByteSealer` (e.g. `KeyringEncryptor` from `starfish-keyring`).
 * @param path    - Push path (starts with `/push/…`).
 * @param bytes   - Plaintext bytes to seal and upload.
 * @param opts    - See {@link SealAndPushBlobOptions}.
 * @returns The server's push result (hash).
 *
 * @throws {RangeError} if `opts.maxBytes` is set and `bytes.length` exceeds it.
 *
 * @example
 * ```ts
 * const result = await sealAndPushBlob(client, enc, objectBlobPush(spaceId, blobId), bytes, {
 *   aad: objectBlobName(spaceId, blobId),
 * })
 * ```
 */
export async function sealAndPushBlob(
  client: StarfishClient,
  sealer: ByteSealer,
  path: string,
  bytes: Uint8Array,
  opts: SealAndPushBlobOptions = {},
): Promise<BlobPushResult> {
  const { aad = documentKey(path), maxBytes } = opts

  if (maxBytes !== undefined && bytes.length > maxBytes) {
    throw new RangeError(
      `sealAndPushBlob: payload is ${bytes.length} bytes — maximum allowed is ${maxBytes} bytes`,
    )
  }

  const sealed = await sealer.sealBytes(bytes, aad)
  return client.pushBlob(path, sealed, "application/octet-stream")
}

// ---------------------------------------------------------------------------
// pullAndOpenBlob
// ---------------------------------------------------------------------------

/** Options for {@link pullAndOpenBlob}. */
export interface PullAndOpenBlobOptions {
  /**
   * Additional authenticated data — must match the AAD used when sealing.
   * Defaults to the document key (pull path with the `/pull/` prefix stripped),
   * which matches the default AAD used by {@link sealAndPushBlob}.
   */
  aad?: string
}

/**
 * Pull a sealed blob from the server and unseal it with `sealer`.
 *
 * @param client - A connected `StarfishClient`.
 * @param sealer - A `ByteSealer` that can open the sealed bytes.
 * @param path   - Pull path (starts with `/pull/…` or is a bare document key).
 * @param opts   - See {@link PullAndOpenBlobOptions}.
 * @returns The original plaintext bytes.
 *
 * @throws if the ciphertext is invalid, tampered with, or the AAD does not match.
 *
 * @example
 * ```ts
 * const bytes = await pullAndOpenBlob(client, enc, objectBlobPull(spaceId, blobId), {
 *   aad: objectBlobName(spaceId, blobId),
 * })
 * ```
 */
export async function pullAndOpenBlob(
  client: StarfishClient,
  sealer: ByteSealer,
  path: string,
  opts: PullAndOpenBlobOptions = {},
): Promise<Uint8Array> {
  const { aad = documentKey(path) } = opts
  const result = await client.pullBlob(path)
  const stored = new Uint8Array(result.data)
  return sealer.openBytes(stored, aad)
}
