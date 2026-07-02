import type { PullResult } from "@drakkar.software/starfish-protocol"
import {
  AUTHOR_PUBKEY_FIELD,
  AUTHOR_SIGNATURE_FIELD,
  PUSH_PATH_PREFIX,
  deepMerge,
  docAuthorCanonicalInput,
  getBase64,
  verifyDocAuthor,
  type AppendAuthor,
} from "@drakkar.software/starfish-protocol"
import type { ConflictResolver } from "./types.js"
import { ConflictError } from "./types.js"
import type { AuthorVerifier } from "./append-log.js"
import type { Encryptor } from "@drakkar.software/starfish-protocol"
import { StarfishClient, stripPushPrefix, pullWasFromCache } from "./client.js"
import type { SyncLogger } from "./logger.js"
import type { Validator } from "./validate.js"
import { ValidationError } from "./validate.js"

export class AbortError extends Error {
  constructor() {
    super("SyncManager was aborted")
    this.name = "AbortError"
  }
}

/** Thrown when a pulled document's author signature fails verification (only
 *  when {@link SyncManagerOptions.verifyAuthor} is enabled). */
export class DocAuthorError extends Error {
  constructor() {
    super("pulled document author verification failed")
    this.name = "DocAuthorError"
  }
}

/**
 * v3.0 author-signature plumbing for `SyncManager`.
 *
 * Returns the device's Ed25519 public key (hex) and a function that signs
 * arbitrary payload bytes. `SyncManager` calls `getSigner()` once per push
 * and uses the returned `sign` to produce a base64-encoded signature over
 * the canonical stringification of the encrypted payload (sans author fields).
 *
 * Implementations typically wrap the same Ed25519 private key used by
 * `StarfishCapProvider` so that `cap.sub === devEdPubHex`.
 */
export interface SyncSigner {
  /**
   * Returns the device's `cap.sub` (Ed25519 pubkey, hex) and a payload signer.
   * The `sign` function receives the canonical signing input bytes and must
   * return the raw 64-byte Ed25519 signature.
   */
  getSigner(): Promise<{ devEdPubHex: string; sign(payload: Uint8Array): Promise<Uint8Array> }>
}


export interface SyncManagerOptions {
  client: StarfishClient
  pullPath: string
  pushPath: string
  /** Custom conflict resolver. Defaults to remote-wins deep merge. Arrays are atomic. */
  onConflict?: ConflictResolver
  /** Max conflict retry attempts (default: 3). */
  maxRetries?: number
  /**
   * Encryptor for client-side E2E encryption. For v3 `delegated` collections,
   * build it via `createKeyringEncryptor(keyring, deviceKemKeys)`.
   */
  encryptor?: Encryptor
  /**
   * v3 author-signature plumbing. When set, every push attaches
   * `authorPubkey` (= `cap.sub`) and `authorSignature` (= base64 Ed25519 over
   * stable-stringify of the encrypted payload minus author fields).
   */
  signer?: SyncSigner
  /** Structured logger for sync events. */
  logger?: SyncLogger
  /** Name passed to logger methods (default: derived from pullPath). */
  loggerName?: string
  /** Validate data before push. Throws ValidationError on failure. */
  validate?: Validator
  /**
   * Opt-in author-signature verification for pulled snapshots. Mirrors
   * {@link AppendLogCursor}'s `verifyAuthor`. Default OFF.
   *
   * TRUST MODEL: with `none`-mode collections the server returns the document
   * `data` alongside the author's Ed25519 `authorPubkey`/`authorSignature`
   * (signed by the writer's device on push over `docAuthorCanonicalInput`).
   * Leaving this off means the client trusts the server not to forge content —
   * fine when the server is trusted, unsafe otherwise. Set `true` to require a
   * valid signature over the pulled `data` for the self-declared `authorPubkey`,
   * or pass `{ expectedAuthorPubkey }` to additionally pin WHICH key must have
   * signed it. A pull/ingest whose signature is missing, foreign, or invalid
   * throws {@link DocAuthorError} and no state is mutated.
   *
   * The signature covers `data` (as stored — ciphertext for `delegated`, so
   * verification runs over the pre-decryption payload) bound to the document
   * key, but NOT `hash`/`timestamp`: a malicious server cannot forge content,
   * but can still replay or re-timestamp an authentic snapshot.
   */
  verifyAuthor?: boolean | AuthorVerifier
}

export class SyncManager {
  private readonly client: StarfishClient
  private readonly pullPath: string
  private readonly pushPath: string
  private readonly onConflict: ConflictResolver
  private readonly maxRetries: number
  private readonly encryptor: Encryptor | null
  private readonly signer?: SyncSigner
  private readonly logger?: SyncLogger
  private readonly loggerName: string
  private readonly validate?: Validator
  private readonly verifyAuthor?: boolean | AuthorVerifier
  private readonly documentKey: string

  private lastHash: string | null = null
  private lastCheckpoint: number = 0
  private localData: Record<string, unknown> = {}
  private aborted: boolean = false
  private lastFromCache: boolean = false
  /** True once {@link seedFromCache} has successfully seeded localData from the cache. */
  private seeded: boolean = false

  constructor(options: SyncManagerOptions) {
    this.client = options.client
    this.pullPath = options.pullPath
    this.pushPath = options.pushPath
    this.onConflict = options.onConflict ?? deepMerge
    this.maxRetries = options.maxRetries ?? 3
    this.signer = options.signer
    this.logger = options.logger
    this.loggerName = options.loggerName ?? options.pullPath.split("/").filter(Boolean).pop() ?? options.pullPath
    this.validate = options.validate
    this.encryptor = options.encryptor ?? null
    this.verifyAuthor = options.verifyAuthor
    // Reader derives the document key by stripping the `/pull/` action prefix —
    // it must match the key the writer signed over (push strips `/push/`).
    this.documentKey = options.pullPath.startsWith("/pull/")
      ? options.pullPath.slice("/pull/".length)
      : options.pullPath
  }

  abort(): void {
    this.aborted = true
  }

  get isAborted(): boolean {
    return this.aborted
  }

  getData(): Record<string, unknown> {
    return { ...this.localData }
  }

  /**
   * Returns true when `pull()` / `ingest()` should merge against the current
   * `localData` rather than replace it wholesale.
   *
   * Two situations establish a merge baseline:
   * - A successful prior pull/ingest advanced `lastCheckpoint` beyond 0 (the
   *   normal steady-state case, unchanged since alpha.36).
   * - A cache seed painted `localData` via {@link seedFromCache} AND the store
   *   uses a custom conflict resolver (i.e. NOT the default `deepMerge`). For a
   *   union/custom resolver the seeded snapshot is a real baseline that must not
   *   be clobbered by a short first live response (a cache-fallback on 429/5xx
   *   or a momentarily-short concurrent server snapshot). For the default
   *   `deepMerge` resolver we keep the pre-fix wholesale-replace behaviour so
   *   non-union stores are byte-identical to alpha.36.
   */
  private hasMergeBaseline(): boolean {
    return this.lastCheckpoint > 0 || (this.seeded && this.onConflict !== deepMerge)
  }

  /**
   * Merge a remote snapshot with local (optimistic) data using this manager's
   * conflict resolver — the same resolver the push-conflict path uses. A plain
   * {@link pull} overwrites the store's data with the server snapshot, which
   * would drop un-pushed local writes (they live only in the store, never in
   * `localData` until a push succeeds). The zustand binding calls this on pull
   * while the store is dirty so those writes survive. `local` wins by the same
   * rules as a push conflict.
   */
  resolve(
    local: Record<string, unknown>,
    remote: Record<string, unknown>,
  ): Record<string, unknown> {
    return this.onConflict(local, remote)
  }

  getHash(): string | null {
    return this.lastHash
  }

  /** Set the last-known server hash. Used by persistence layers to restore state across restarts. */
  setHash(hash: string | null): void {
    this.lastHash = hash
  }

  /**
   * Whether the most recent {@link pull} (or {@link seedFromCache}) was served
   * from the client's offline read-through cache rather than a live server
   * response. The binding surfaces this as a `stale` flag so the UI can show an
   * offline indicator without treating a cache hit as "reachable". Reset to
   * false by the next successful network pull.
   */
  getLastPullFromCache(): boolean {
    return this.lastFromCache
  }

  /**
   * Cache-first paint: seed `localData` from the client's read-through cache
   * WITHOUT touching the network, decrypting in memory for E2E collections.
   * Returns whether anything was seeded (false on a miss, an expired entry, or
   * a decrypt failure — e.g. keyring skew). Call once on store creation before
   * the initial live {@link pull}.
   *
   * `lastCheckpoint` is intentionally left at 0 so the first live pull sends a
   * full (re)sync request to the server, not a delta. However, for stores with
   * a custom conflict resolver (e.g. `createUnionMerge`) the seeded snapshot is
   * treated as a merge baseline: {@link hasMergeBaseline} returns true, so the
   * first pull/ingest merges against the seed rather than replacing it wholesale.
   * This closes the bootstrap window where a short first-pull response (a cache-
   * fallback on 429/5xx or a momentarily-short concurrent snapshot) would
   * silently drop items the resolver was configured to preserve. For the default
   * `deepMerge` resolver the first pull still takes the snapshot wholesale —
   * behaviour is byte-identical to alpha.36.
   *
   * Requires the client to have been built with a `cache`.
   */
  async seedFromCache(): Promise<boolean> {
    if (this.aborted) return false
    const cached = await this.client.peekCache(this.pullPath)
    if (!cached) return false
    let data: Record<string, unknown>
    try {
      data = this.encryptor ? await this.encryptor.decrypt(cached.data) : cached.data
    } catch {
      return false // undecryptable (keyring skew / foreign epoch) — seed nothing
    }
    if (this.aborted) return false
    this.localData = data
    this.lastHash = cached.hash
    // Mark the seed so hasMergeBaseline() can protect it for custom resolvers.
    // lastCheckpoint stays 0: the first live pull is a full resync (checkpoint=0
    // in the query), not a delta against a possibly-stale cache timestamp.
    this.seeded = true
    this.lastFromCache = true
    return true
  }

  getCheckpoint(): number {
    return this.lastCheckpoint
  }

  /**
   * Apply a freshly-fetched `PullResult` to this manager's state WITHOUT
   * firing a network request. Used by the zustand binding's `mergeResult`
   * action to absorb a background revalidation result (delivered via
   * {@link StarfishClientOptions.onRevalidated}) into the store.
   *
   * Like {@link pull}, `ingest` conflict-merges the snapshot against the
   * established baseline via `this.onConflict` when a merge baseline exists
   * ({@link hasMergeBaseline}) — so a union-merge store does not lose array
   * items when a revalidation result (e.g. a stale cache-fallback on 429/5xx)
   * is a shorter snapshot. The baseline is established by either a prior
   * pull/ingest that advanced `lastCheckpoint`, or by a successful
   * {@link seedFromCache} for a store with a custom resolver. The first ingest
   * without such a baseline takes the snapshot wholesale (default `deepMerge`
   * stores are byte-identical to alpha.36). Sets `lastFromCache = false` (a
   * revalidation is a live response) so the binding can clear its `stale` flag.
   *
   * **Staleness guard**: if a `push()` advanced `lastCheckpoint` between the
   * time the revalidation request was sent and the time it resolves, the
   * result is from an older document version. Ingesting it would clobber the
   * user's just-saved edit and reset `lastHash` to a stale server hash
   * (causing a spurious 409 on the next push). We silently drop the result in
   * that case — the store's post-push state is already correct.
   */
  /**
   * Verify a pulled snapshot's author signature over its RAW (pre-decryption)
   * `data`, bound to the document key. Throws {@link DocAuthorError} on any
   * failure. No-op when {@link SyncManagerOptions.verifyAuthor} is disabled.
   */
  private verifyAuthorProof(result: PullResult): void {
    if (!this.verifyAuthor) return
    const policy: AuthorVerifier = typeof this.verifyAuthor === "object" ? this.verifyAuthor : {}
    const { authorPubkey, authorSignature } = result
    if (!authorPubkey || !authorSignature) throw new DocAuthorError()
    // Public keys are hex (case-insensitive) — normalise before comparing so a
    // differently-cased `expectedAuthorPubkey` isn't falsely rejected.
    if (
      policy.expectedAuthorPubkey &&
      authorPubkey.toLowerCase() !== policy.expectedAuthorPubkey.toLowerCase()
    ) {
      throw new DocAuthorError()
    }
    const ok = verifyDocAuthor(
      this.documentKey,
      result.data as Record<string, unknown>,
      authorPubkey,
      authorSignature,
    )
    if (!ok) throw new DocAuthorError()
  }

  async ingest(result: PullResult): Promise<void> {
    if (this.aborted) return
    // Drop a revalidation result that is older than our current local state.
    // `lastCheckpoint` is advanced by every successful push() and pull(); a
    // revalidation snapshot whose document timestamp is strictly less than the
    // current checkpoint is stale relative to a concurrent push.
    if (result.timestamp < this.lastCheckpoint) return
    // Verify authorship over the raw (pre-decryption) data before accepting it.
    this.verifyAuthorProof(result)
    let incoming: Record<string, unknown>
    if (this.encryptor) {
      incoming = await this.encryptor.decrypt(result.data)
      if (this.aborted) return
    } else {
      incoming = result.data
    }
    // Honor the configured conflict resolver against the established baseline
    // (same as pull()). The first ingest takes the snapshot wholesale unless a
    // prior cache seed established a baseline for a custom resolver.
    this.localData = this.hasMergeBaseline() ? this.onConflict(this.localData, incoming) : incoming
    this.lastHash = result.hash
    this.lastCheckpoint = result.timestamp
    this.lastFromCache = false
  }

  async pull(): Promise<PullResult> {
    if (this.aborted) throw new AbortError()
    this.logger?.pullStart(this.loggerName)
    const start = performance.now()
    try {
      // NOTE: `SyncManager.pull` does NOT auto-enable `withKeyring`. Clients
      // that drive the keyring helpers from `recipients.ts` and want to save
      // the cold-start round-trip should call `client.pull(path, {withKeyring: true})`
      // directly. We keep `SyncManager` keyring-agnostic so it stays usable
      // for collections that don't use delegated encryption.
      const result = await this.client.pull(this.pullPath, this.lastCheckpoint)
      if (this.aborted) throw new AbortError()
      // True when the client served this from its offline cache (transport was
      // unreachable); a live response clears it. Surfaced as `stale` by the binding.
      this.lastFromCache = pullWasFromCache(result)

      // Verify authorship over the raw (pre-decryption) data before accepting it.
      this.verifyAuthorProof(result)

      let incoming: Record<string, unknown>
      if (this.encryptor) {
        incoming = await this.encryptor.decrypt(result.data)
        if (this.aborted) throw new AbortError()
      } else {
        incoming = result.data
      }
      // Honor the configured conflict resolver against the established baseline —
      // the same resolver the push-conflict path (push 409 / resolve()) already
      // uses. A union-merge store must not lose array items when a pull returns a
      // shorter/stale snapshot (cache-fallback on 429/5xx or a momentarily-short
      // concurrent write). hasMergeBaseline() returns true when either a prior
      // pull/ingest advanced lastCheckpoint OR a cache seed established a baseline
      // for a custom resolver. The first pull without a prior seed (or with the
      // default deepMerge) takes the snapshot wholesale — byte-identical to
      // alpha.36 for stores without a custom resolver.
      this.localData = this.hasMergeBaseline() ? this.onConflict(this.localData, incoming) : incoming
      result.data = this.localData

      this.lastHash = result.hash
      this.lastCheckpoint = result.timestamp
      this.logger?.pullSuccess(this.loggerName, Math.round(performance.now() - start))
      return result
    } catch (err) {
      this.logger?.pullError(this.loggerName, err instanceof Error ? err.message : String(err))
      throw err
    }
  }

  async push(data: Record<string, unknown>): Promise<{ hash: string; timestamp: number }> {
    if (this.aborted) throw new AbortError()
    if (this.validate) {
      const result = this.validate(data)
      if (result !== true) throw new ValidationError(result)
    }
    this.logger?.pushStart(this.loggerName)
    const start = performance.now()
    let attempt = 0
    let pendingData = data

    while (attempt <= this.maxRetries) {
      try {
        const sealed = this.encryptor
          ? await this.encryptor.encrypt(pendingData)
          : pendingData
        if (this.aborted) throw new AbortError()

        // v3.0 signer path: sign the document author proof over the doc-author
        // canonical input (domain-tagged, bound to documentKey) and pass it as
        // top-level body siblings of `data` (NOT inside `data`), where the server
        // verifies it and stores the raw author pubkey.
        let author: AppendAuthor | undefined
        if (this.signer) {
          const { devEdPubHex, sign } = await this.signer.getSigner()
          if (this.aborted) throw new AbortError()
          const documentKey = stripPushPrefix(this.pushPath)
          const canonical = docAuthorCanonicalInput(documentKey, sealed as Record<string, unknown>)
          const sigBytes = await sign(new TextEncoder().encode(canonical))
          if (this.aborted) throw new AbortError()
          author = {
            [AUTHOR_PUBKEY_FIELD]: devEdPubHex,
            [AUTHOR_SIGNATURE_FIELD]: getBase64().encode(sigBytes),
          }
        }

        const result = await this.client.push(
          this.pushPath,
          sealed as Record<string, unknown>,
          this.lastHash,
          author,
        )
        if (this.aborted) throw new AbortError()
        this.lastHash = result.hash
        this.lastCheckpoint = result.timestamp
        this.localData = pendingData
        this.logger?.pushSuccess(this.loggerName, Math.round(performance.now() - start))
        return result
      } catch (err) {
        if (err instanceof AbortError) throw err
        if (!(err instanceof ConflictError) || attempt >= this.maxRetries) {
          this.logger?.pushError(this.loggerName, err instanceof Error ? err.message : String(err))
          throw err
        }
        this.logger?.conflict(this.loggerName, attempt + 1)
        try {
          const remote = await this.client.pull(this.pullPath)
          if (this.aborted) throw new AbortError()
          const remoteData = this.encryptor
            ? await this.encryptor.decrypt(remote.data)
            : remote.data
          if (this.aborted) throw new AbortError()
          this.lastHash = remote.hash
          this.lastCheckpoint = remote.timestamp
          pendingData = this.onConflict(pendingData, remoteData)
        } catch (resolveErr) {
          if (resolveErr instanceof AbortError) throw resolveErr
          const msg = resolveErr instanceof Error ? resolveErr.message : String(resolveErr)
          this.logger?.pushError(this.loggerName, `Conflict resolution failed (attempt ${attempt + 1}): ${msg}`)
          throw resolveErr
        }
        await new Promise<void>(resolve => setTimeout(resolve, Math.min(100 * Math.pow(2, attempt), 2000) + Math.random() * 100))
        attempt++
      }
    }
    throw new ConflictError()
  }

  async update(
    modifier: (current: Record<string, unknown>) => Record<string, unknown>
  ): Promise<{ hash: string; timestamp: number }> {
    await this.pull()
    const updated = modifier(this.localData)
    return this.push(updated)
  }
}
