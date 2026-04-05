import { AbstractObjectStore } from "./base.js"
import * as fs from "node:fs/promises"
import * as path from "node:path"
import * as os from "node:os"
import * as crypto from "node:crypto"

const VALID_KEY = /^[a-zA-Z0-9_\-.:@/]+$/

export interface FilesystemStorageOptions {
  baseDir: string
}

export class FilesystemObjectStore extends AbstractObjectStore {
  private readonly baseDir: string

  constructor(options: FilesystemStorageOptions) {
    super()
    this.baseDir = options.baseDir
  }

  private validateKey(key: string): void {
    if (!VALID_KEY.test(key) || key.includes("..")) {
      throw new Error(`Invalid key: ${key}`)
    }
  }

  private resolvePath(key: string): string {
    this.validateKey(key)
    return path.join(this.baseDir, key)
  }

  async getString(key: string): Promise<string | null> {
    try {
      return await fs.readFile(this.resolvePath(key), "utf-8")
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null
      throw err
    }
  }

  async put(
    key: string,
    body: string,
    _options?: { contentType?: string; cacheControl?: string },
  ): Promise<void> {
    const filePath = this.resolvePath(key)
    await fs.mkdir(path.dirname(filePath), { recursive: true })
    const tmpPath = path.join(os.tmpdir(), `starfish-${crypto.randomUUID()}`)
    await fs.writeFile(tmpPath, body, "utf-8")
    await fs.rename(tmpPath, filePath)
  }

  async listKeys(
    prefix: string,
    options?: { startAfter?: string; limit?: number },
  ): Promise<string[]> {
    const dir = path.join(this.baseDir, prefix)
    let entries: string[]
    try {
      entries = await fs.readdir(dir)
    } catch {
      return []
    }
    let keys = entries.map((e) => (prefix ? `${prefix}${e}` : e)).sort()
    if (options?.startAfter) {
      keys = keys.filter((k) => k > options.startAfter!)
    }
    if (options?.limit !== undefined) {
      keys = keys.slice(0, options.limit)
    }
    return keys
  }

  async delete(key: string): Promise<void> {
    try {
      await fs.unlink(this.resolvePath(key))
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err
    }
    try {
      await fs.unlink(this.resolvePath(key + ".__meta__"))
    } catch {
      // ignored
    }
  }

  async deleteMany(keys: string[]): Promise<void> {
    await Promise.all(keys.map((key) => this.delete(key)))
  }

  async getBytes(key: string): Promise<{ data: Buffer; contentType: string } | null> {
    try {
      const data = await fs.readFile(this.resolvePath(key))
      let contentType = "application/octet-stream"
      try {
        contentType = await fs.readFile(this.resolvePath(key + ".__meta__"), "utf-8")
      } catch {
        // no meta
      }
      return { data: Buffer.from(data), contentType }
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null
      throw err
    }
  }

  async putBytes(
    key: string,
    body: Buffer,
    options: { contentType: string; cacheControl?: string },
  ): Promise<void> {
    const filePath = this.resolvePath(key)
    await fs.mkdir(path.dirname(filePath), { recursive: true })
    await fs.writeFile(filePath, body)
    await fs.writeFile(this.resolvePath(key + ".__meta__"), options.contentType, "utf-8")
  }
}
