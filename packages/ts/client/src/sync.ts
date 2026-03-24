import type { PullResult } from "@starfish/protocol"
import { deepMerge, stableStringify } from "@starfish/protocol"
import type { ConflictResolver } from "./types.js"
import { ConflictError } from "./types.js"
import { StarfishClient } from "./client.js"
import type { Encryptor } from "./crypto.js"
import { createEncryptor } from "./crypto.js"


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
  signData?: (data: string) => Promise<string>
}

export class SyncManager {
  private readonly client: StarfishClient
  private readonly pullPath: string
  private readonly pushPath: string
  private readonly onConflict: ConflictResolver
  private readonly maxRetries: number
  private readonly encryptor: Encryptor | null
  private readonly signData?: (data: string) => Promise<string>

  private lastHash: string | null = null
  private lastCheckpoint: number = 0
  private localData: Record<string, unknown> = {}

  constructor(options: SyncManagerOptions) {
    this.client = options.client
    this.pullPath = options.pullPath
    this.pushPath = options.pushPath
    this.onConflict = options.onConflict ?? deepMerge
    this.maxRetries = options.maxRetries ?? 3
    this.signData = options.signData
    this.encryptor =
      options.encryptionSecret && options.encryptionSalt
        ? createEncryptor(options.encryptionSecret, options.encryptionSalt, options.encryptionInfo)
        : null
  }

  getData(): Record<string, unknown> {
    return { ...this.localData }
  }

  getHash(): string | null {
    return this.lastHash
  }

  getCheckpoint(): number {
    return this.lastCheckpoint
  }

  async pull(): Promise<PullResult> {
    const result = await this.client.pull(this.pullPath, this.lastCheckpoint)

    if (this.encryptor) {
      const decrypted = await this.encryptor.decrypt(result.data)
      this.localData = decrypted
      result.data = decrypted
    } else if (this.lastCheckpoint > 0) {
      this.localData = deepMerge(this.localData, result.data)
    } else {
      this.localData = result.data
    }

    this.lastHash = result.hash
    this.lastCheckpoint = result.timestamp
    return result
  }

  async push(data: Record<string, unknown>): Promise<{ hash: string; timestamp: number }> {
    let attempt = 0
    let pendingData = data

    while (attempt <= this.maxRetries) {
      try {
        const payload = this.encryptor
          ? await this.encryptor.encrypt(pendingData)
          : pendingData

        const sig = this.signData
          ? await this.signData(stableStringify(payload))
          : undefined

        const result = await this.client.push(
          this.pushPath,
          payload,
          this.lastHash,
          sig
        )
        this.lastHash = result.hash
        this.lastCheckpoint = result.timestamp
        this.localData = pendingData
        return result
      } catch (err) {
        if (!(err instanceof ConflictError) || attempt >= this.maxRetries) {
          throw err
        }
        const remote = await this.client.pull(this.pullPath)
        this.lastHash = remote.hash
        this.lastCheckpoint = remote.timestamp

        const remoteData = this.encryptor
          ? await this.encryptor.decrypt(remote.data)
          : remote.data
        pendingData = this.onConflict(pendingData, remoteData)
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
