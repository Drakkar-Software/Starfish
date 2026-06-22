/**
 * Live StarfishClient adapters for `@drakkar.software/starfish-wal`.
 *
 * The `starfish-wal` package ships only the CRDT engine and the injection
 * *interfaces* (`WalTransport`, `WalSnapshotStore`, `WalEncryptor`,
 * `WalSigner`). This module provides the canonical wiring of those interfaces
 * to a live `StarfishClient`, so every consumer does not have to re-implement
 * the same boilerplate.
 *
 * Exported via `@drakkar.software/starfish-wal/client` so apps that do NOT
 * use WAL documents can exclude this module (and its `starfish-client` peer
 * dependency) from their bundle.
 *
 * @module starfish-wal/client
 *
 * @example
 * ```ts
 * import { createWalDocument } from "@drakkar.software/starfish-wal/client"
 *
 * const doc = createWalDocument({
 *   client,
 *   documentKey: "spaces/sp-123/pages/pg-456",
 *   edPubHex: device.edPubHex,
 *   edPrivHex: device.edPrivHex,
 *   encryptor: spaceKeyring,      // null for a public (plaintext) space
 *   withSnapshots: true,
 * })
 *
 * await doc.open()
 * doc.dispatch([{ type: "set", path: ["title"], value: "Hello" }])
 * ```
 */
import type {
  WalEncryptor,
  WalSnapshotDoc,
  WalSnapshotStore,
  WalTransport,
  WalAppendElement,
  ReaderPosture,
} from "./document.js"
import { WalDocument, createEd25519Signer, noopEncryptor } from "./document.js"

// ── Peer-dep types (kept as type-only imports so the wal core itself stays
//    free of a hard starfish-client runtime dep) ────────────────────────────

/**
 * Minimal StarfishClient surface used by the WAL adapters.
 *
 * The `pull` method follows the same overload pattern as `StarfishClient.pull`:
 * - Without a second argument (or with a numeric checkpoint): returns a
 *   structured pull `{ data, hash, timestamp }`.
 * - With an `AppendPullOptions`-like object (recognizable by the absence of a
 *   `checkpoint` key): returns the extracted array of elements directly.
 *
 * Using `unknown` for the return keeps the interface adapter-friendly — the
 * WAL adapters cast appropriately for each usage.
 */
export interface WalStarfishClient {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  pull(path: string, opts?: Record<string, unknown>): Promise<any>
  push(
    path: string,
    data: Record<string, unknown>,
    baseHash: string | null,
  ): Promise<{ hash?: string | null; timestamp?: number }>
  append(path: string, data: Record<string, unknown>): Promise<{ timestamp: number }>
}

/** Minimal Encryptor surface (same shape as starfish-protocol's Encryptor). */
export interface WalEncryptorSource {
  encrypt(data: Record<string, unknown>): Promise<Record<string, unknown>>
  decrypt(data: Record<string, unknown>): Promise<Record<string, unknown>>
}

// ── ConflictError duck-type ───────────────────────────────────────────────────
//
// Rather than importing ConflictError from starfish-client (which would make
// this module depend on the client at runtime), we duck-type it: any Error
// whose `.name === "ConflictError"` or whose message contains the canonical
// "hash_mismatch" token is treated as a retryable conflict. This matches the
// actual ConflictError class from starfish-client exactly.

function isConflict(err: unknown): boolean {
  if (!(err instanceof Error)) return false
  return (
    err.name === "ConflictError" ||
    /hash_mismatch|conflict|stale|412|409/i.test(err.message)
  )
}

// ── createWalTransport ────────────────────────────────────────────────────────

/**
 * Build a {@link WalTransport} backed by a live `StarfishClient`.
 *
 * - `append` → `client.append("/push/<documentKey>", body.data)`.  The client
 *   auto-signs the element with the cap's device key, which MUST be the same
 *   Ed25519 key the WAL {@link createEd25519Signer} uses — so the stored
 *   element's author proof is the one a reader verifies.
 * - `pull` → a one-shot stateless cursor over `client.pull` (with `?since=`),
 *   returning raw elements (ciphertext `data` + `ts` + author fields).
 *   `WalDocument` decrypts and verifies the author proof itself.
 *
 * A 404 from the server means the collection has never been written — treated
 * as an empty starting state, not an error. Every other HTTP error propagates.
 *
 * @param client  A `StarfishClient` instance (or any compatible object).
 */
export function createWalTransport(client: WalStarfishClient): WalTransport {
  return {
    async append(documentKey, body) {
      const res = await client.append(`/push/${documentKey}`, body.data as Record<string, unknown>)
      return { ts: res.timestamp }
    },

    async pull(documentKey, checkpoint) {
      // We use client.pull with AppendPullOptions to get elements since the
      // last known position. The absence of a `checkpoint` key (and presence of
      // `since`) signals the append overload — client.pull returns a raw T[].
      // A 404 means the collection has never been written; treat as empty.
      let items: Array<{
        ts?: number
        data?: unknown
        authorPubkey?: string
        authorSignature?: string
      }>
      try {
        // AppendPullOptions: { since } (not { checkpoint }) triggers the array overload.
        const result = await client.pull(`/pull/${documentKey}`, { since: checkpoint })
        // client.pull in append mode returns the extracted array directly.
        items = result as typeof items
      } catch (err) {
        const status =
          err != null && typeof err === "object" && "status" in err
            ? (err as { status: number }).status
            : 0
        if (status === 404) return []
        throw err
      }
      return items.map<WalAppendElement>((e) => ({
        ts: e.ts ?? 0,
        data: (e.data ?? {}) as Record<string, unknown>,
        authorPubkey: e.authorPubkey ?? "",
        authorSignature: e.authorSignature ?? "",
      }))
    },
  }
}

// ── createWalSnapshotStore ────────────────────────────────────────────────────

const WAL_SNAPSHOT_MAX_ATTEMPTS = 3

/**
 * Build a {@link WalSnapshotStore} backed by a regular LWW document at
 * `<documentKey>__snapshot`.
 *
 * The snapshot doc is a normal non-append collection: `read` pulls the current
 * doc and `write` does a hash-CAS push with retry on conflict. The document
 * carries the WAL-produced `WalSnapshotDoc` verbatim — it already contains
 * its own `producedBy` + author signature for reader verification.
 *
 * CAS retry uses `instanceof`-compatible duck-typing for `ConflictError`
 * (name or message match) to avoid a hard runtime dependency on starfish-client.
 *
 * @param client  A `StarfishClient` instance (or any compatible object).
 */
export function createWalSnapshotStore(client: WalStarfishClient): WalSnapshotStore {
  return {
    async read(snapshotKey) {
      // Snapshot doc is a structured (non-append) pull — no options arg → returns {data, hash, timestamp}.
      let res: { data?: unknown; hash?: string | null } | null = null
      try {
        res = await client.pull(`/pull/${snapshotKey}`) as { data?: unknown; hash?: string | null }
      } catch {
        return null
      }
      const data = (res?.data ?? null) as Partial<WalSnapshotDoc> | null
      if (!data || typeof data.uptoTs !== "number" || !data.state) return null
      return data as WalSnapshotDoc
    },

    async write(snapshotKey, doc) {
      let lastErr: unknown
      for (let attempt = 0; attempt < WAL_SNAPSHOT_MAX_ATTEMPTS; attempt++) {
        // Always re-pull the latest hash before each attempt so concurrent
        // writers don't permanently conflict each other.
        let base: string | null = null
        try {
          const cur = await client.pull(`/pull/${snapshotKey}`) as { hash?: string | null }
          base = cur.hash ?? null
        } catch {
          // 404 or network error — proceed with null base (first write).
        }

        try {
          await client.push(
            `/push/${snapshotKey}`,
            doc as unknown as Record<string, unknown>,
            base,
          )
          return // success
        } catch (err) {
          lastErr = err
          if (isConflict(err) && attempt < WAL_SNAPSHOT_MAX_ATTEMPTS - 1) {
            continue // retry with fresh hash
          }
          throw err
        }
      }
      throw lastErr
    },
  }
}

// ── walEncryptorFromKeyring ───────────────────────────────────────────────────

/**
 * Adapt a starfish-keyring `Encryptor` (`{encrypt, decrypt}`) to the
 * `WalEncryptor` interface (`{seal, open}`).
 *
 * Under `encryption: "delegated"` (a private space) each op-batch and
 * snapshot `state` are sealed with the space's CEK — exactly like any other
 * space document. Under `encryption: "none"` pass `null` and use the package's
 * {@link noopEncryptor} (exported for convenience).
 */
export function walEncryptorFromKeyring(enc: WalEncryptorSource): WalEncryptor {
  return {
    seal: (plain) => enc.encrypt(plain as Record<string, unknown>),
    open: (sealed) => enc.decrypt(sealed as Record<string, unknown>),
  }
}

export { noopEncryptor }

// ── walSignerFromKeys ─────────────────────────────────────────────────────────

/**
 * Build a `WalSigner` from a device's Ed25519 keypair.
 *
 * {@link createEd25519Signer} reuses `signAppendAuthor` / `signDocAuthor`
 * from starfish-protocol, so the proof is byte-identical to what
 * `StarfishClient.append` signs automatically — the client's auto-signed
 * author and the WAL author proof agree on the same key.
 *
 * Pass the same `edPubHex` / `edPrivHex` that the client's cap was issued to.
 */
export { createEd25519Signer as walSignerFromKeys }

// ── createWalDocument ─────────────────────────────────────────────────────────

/** Options for {@link createWalDocument}. */
export interface CreateWalDocumentOptions {
  /** A `StarfishClient` instance (or compatible object). */
  client: WalStarfishClient
  /**
   * Bare storage key — e.g. `"spaces/{spaceId}/objects/pages/{objectId}"`.
   * The transport appends `/push/` or `/pull/` prefixes internally.
   */
  documentKey: string
  /** This device's Ed25519 signing public key (hex). */
  edPubHex: string
  /** This device's Ed25519 signing private key (hex). */
  edPrivHex: string
  /**
   * Space keyring `Encryptor` for a private (delegated-encryption) space.
   * Omit or pass `null` for a public (plaintext) space — `noopEncryptor` is
   * used automatically.
   */
  encryptor?: WalEncryptorSource | null
  /**
   * Per-session nonce to disambiguate replica ids on the same device (e.g.
   * when the same user opens a document in two tabs). Defaults to the
   * `WalDocument` default (`"0"`).
   */
  sessionNonce?: string
  /**
   * Whether to enable the sibling snapshot document for fast cold-start and
   * background compaction. Default `true`. Set to `false` to skip snapshots
   * (e.g. in read-only clients or tests).
   */
  withSnapshots?: boolean
  /** Reader posture for handling sequence gaps. Default `"trust-retain-tail"`. */
  posture?: ReaderPosture
}

/**
 * Assemble a fully-wired {@link WalDocument} from a `StarfishClient` and
 * device keys.
 *
 * This is the one-call factory that most consumers need:
 *
 * ```ts
 * const doc = createWalDocument({ client, documentKey, edPubHex, edPrivHex })
 * await doc.open()
 * doc.dispatch([{ type: "set", path: ["title"], value: "My page" }])
 * ```
 *
 * Under the hood it wires together:
 * - `createWalTransport(client)` — append-log read/write over `StarfishClient`
 * - `createWalSnapshotStore(client)` — cold-start LWW snapshot (CAS-safe)
 * - `walSignerFromKeys(edPubHex, edPrivHex)` — Ed25519 author proof
 * - `walEncryptorFromKeyring(encryptor)` or `noopEncryptor`
 */
export function createWalDocument(opts: CreateWalDocumentOptions): WalDocument {
  const encryptor: WalEncryptor = opts.encryptor
    ? walEncryptorFromKeyring(opts.encryptor)
    : noopEncryptor

  const snapshotStore: WalSnapshotStore | undefined =
    opts.withSnapshots === false ? undefined : createWalSnapshotStore(opts.client)

  return new WalDocument({
    documentKey: opts.documentKey,
    transport: createWalTransport(opts.client),
    signer: createEd25519Signer(opts.edPubHex, opts.edPrivHex),
    encryptor,
    snapshotStore,
    sessionNonce: opts.sessionNonce,
    posture: opts.posture ?? "trust-retain-tail",
  })
}
