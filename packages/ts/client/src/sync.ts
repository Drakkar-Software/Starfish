import type { PullResult } from "@drakkar.software/starfish-protocol"
import { deepMerge, stableStringify } from "@drakkar.software/starfish-protocol"
import type { ConflictResolver } from "./types.js"
import { ConflictError } from "./types.js"
import { StarfishClient } from "./client.js"
import type { Encryptor } from "./crypto.js"
import { createEncryptor } from "./crypto.js"
import type { SyncLogger } from "./logger.js"
import type { Validator } from "./validate.js"
import { ValidationError } from "./validate.js"

export class AbortError extends Error {
  constructor() {
    super("SyncManager was aborted")
    this.name = "AbortError"
  }
}


export interface SyncManagerOptions {
  client: StarfishClient
  pullPath: string
  pushPath: string
  /** Custom conflict resolver. Defaults to remote-wins deep merge. Arrays are atomic. */
  onConflict?: ConflictResolver
  /** Max conflict retry attempts (default: 3). */
  maxRetries?: number
  encryptionSecret?: string
  encryptionSalt?: string
  encryptionInfo?: string
  /**
   * Pre-created Encryptor. Use this with `createGroupEncryptor` for group encryption.
   * Takes precedence over `encryptionSecret` / `encryptionSalt` if both are provided.
   */
  encryptor?: Encryptor
  signData?: (data: string) => Promise<string>
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
  private readonly signData?: (data: string) => Promise<string>
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
    this.signData = options.signData
    this.logger = options.logger
    this.loggerName = options.loggerName ?? options.pullPath.split("/").filter(Boolean).pop() ?? options.pullPath
    this.validate = options.validate
    this.encryptor =
      options.encryptor ??
      (options.encryptionSecret && options.encryptionSalt
        ? createEncryptor(options.encryptionSecret, options.encryptionSalt, options.encryptionInfo)
        : null)
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
        const payload = this.encryptor
          ? await this.encryptor.encrypt(pendingData)
          : pendingData
        if (this.aborted) throw new AbortError()

        const sig = this.signData
          ? await this.signData(stableStringify(payload))
          : undefined
        if (this.aborted) throw new AbortError()

        const result = await this.client.push(
          this.pushPath,
          payload,
          this.lastHash,
          sig
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
