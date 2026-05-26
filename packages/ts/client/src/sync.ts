import type { PullResult } from "@drakkar.software/starfish-protocol"
import {
  AUTHOR_PUBKEY_FIELD,
  AUTHOR_SIGNATURE_FIELD,
  PUSH_PATH_PREFIX,
  deepMerge,
  docAuthorCanonicalInput,
  getBase64,
  type AppendAuthor,
} from "@drakkar.software/starfish-protocol"
import type { ConflictResolver } from "./types.js"
import { ConflictError } from "./types.js"
import type { Encryptor } from "@drakkar.software/starfish-protocol"
import { StarfishClient, stripPushPrefix } from "./client.js"
import type { SyncLogger } from "./logger.js"
import type { Validator } from "./validate.js"
import { ValidationError } from "./validate.js"

export class AbortError extends Error {
  constructor() {
    super("SyncManager was aborted")
    this.name = "AbortError"
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

  private lastHash: string | null = null
  private lastCheckpoint: number = 0
  private localData: Record<string, unknown> = {}
  private aborted: boolean = false

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

  getHash(): string | null {
    return this.lastHash
  }

  /** Set the last-known server hash. Used by persistence layers to restore state across restarts. */
  setHash(hash: string | null): void {
    this.lastHash = hash
  }

  getCheckpoint(): number {
    return this.lastCheckpoint
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

      if (this.encryptor) {
        const decrypted = await this.encryptor.decrypt(result.data)
        if (this.aborted) throw new AbortError()
        this.localData = decrypted
        result.data = decrypted
      } else if (this.lastCheckpoint > 0) {
        this.localData = deepMerge(this.localData, result.data)
        result.data = this.localData
      } else {
        this.localData = result.data
      }

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
