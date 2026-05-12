import { readFile, writeFile, mkdir, rm, readdir, stat, rename } from "node:fs/promises"
import { join, dirname, relative, sep } from "node:path"
import { resolve } from "node:path"
import type { ObjectStore, StoreContext } from "./base.js"

const VALID_KEY = /^[a-zA-Z0-9._:@\-/]+$/

function validateKey(key: string): void {
  if (!key || !VALID_KEY.test(key) || key.split("/").includes("..")) {
    throw new Error(`Invalid storage key: "${key}"`)
  }
}

export interface FilesystemStorageOptions {
  baseDir: string
}

export class FilesystemObjectStore implements ObjectStore {
  private _base: string

  constructor(opts: FilesystemStorageOptions) {
    this._base = resolve(opts.baseDir)
  }

  private _path(key: string): string {
    validateKey(key)
    return join(this._base, ...key.split("/"))
  }

  async getString(key: string, _context?: StoreContext): Promise<string | null> {
    const path = this._path(key)
    try {
      return await readFile(path, "utf-8")
    } catch (e: any) {
      if (e.code === "ENOENT") return null
      throw e
    }
  }

  async put(key: string, body: string, _opts?: { contentType?: string; cacheControl?: string }, _context?: StoreContext): Promise<void> {
    const path = this._path(key)
    await mkdir(dirname(path), { recursive: true })
    const tmp = path + ".tmp"
    try {
      await writeFile(tmp, body, "utf-8")
      await rename(tmp, path)
    } catch (e) {
      try { await rm(tmp, { force: true }) } catch { /* ignore */ }
      throw e
    }
  }

  async getBytes(key: string, _context?: StoreContext): Promise<{ body: Uint8Array; contentType: string } | null> {
    const path = this._path(key)
    let body: Uint8Array
    try {
      body = new Uint8Array(await readFile(path))
    } catch (e: any) {
      if (e.code === "ENOENT") return null
      throw e
    }
    let contentType = "application/octet-stream"
    try {
      const meta = JSON.parse(await readFile(path + ".__meta__", "utf-8"))
      contentType = meta.contentType ?? contentType
    } catch (e: any) {
      if (e.code !== "ENOENT" && !(e instanceof SyntaxError)) {
        console.error(`[Starfish] Error reading metadata for "${key}":`, e)
      }
    }
    return { body, contentType }
  }

  async putBytes(
    key: string,
    body: Uint8Array,
    opts: { contentType: string },
    _context?: StoreContext,
  ): Promise<void> {
    const path = this._path(key)
    await mkdir(dirname(path), { recursive: true })
    const tmp = path + ".tmp"
    try {
      await writeFile(tmp, body)
      await rename(tmp, path)
    } catch (e) {
      try { await rm(tmp, { force: true }) } catch { /* ignore */ }
      throw e
    }
    // Write sidecar metadata
    const metaPath = path + ".__meta__"
    const metaTmp = metaPath + ".tmp"
    try {
      await writeFile(metaTmp, JSON.stringify({ contentType: opts.contentType }), "utf-8")
      await rename(metaTmp, metaPath)
    } catch (e) {
      try { await rm(metaTmp, { force: true }) } catch { /* ignore */ }
      throw e
    }
  }

  async listKeys(
    prefix: string,
    opts?: { startAfter?: string; limit?: number },
    _context?: StoreContext,
  ): Promise<string[]> {
    validateKey(prefix)
    const prefixPath = join(this._base, ...prefix.split("/"))

    let stats
    try {
      stats = await stat(prefixPath)
    } catch (e: any) {
      if (e.code === "ENOENT") return []
      throw e
    }

    if (stats.isFile()) {
      if (opts?.startAfter == null || prefix > opts.startAfter) return [prefix]
      return []
    }

    if (!stats.isDirectory()) return []

    const results: string[] = []
    const walk = async (dir: string): Promise<void> => {
      const entries = await readdir(dir, { withFileTypes: true })
      for (const entry of [...entries].sort((a: { name: string }, b: { name: string }) => a.name.localeCompare(b.name))) {
        const fullPath = join(dir, entry.name)
        if (entry.isDirectory()) {
          await walk(fullPath)
        } else {
          if (entry.name.endsWith(".tmp") || entry.name.endsWith(".__meta__")) continue
          const rel = relative(this._base, fullPath).split(sep).join("/")
          if (!rel.startsWith(prefix)) continue
          if (opts?.startAfter != null && rel <= opts.startAfter) continue
          results.push(rel)
        }
      }
    }

    await walk(prefixPath)
    results.sort()
    if (opts?.limit != null) return results.slice(0, opts.limit)
    return results
  }

  async delete(key: string, _context?: StoreContext): Promise<void> {
    const path = this._path(key)
    await rm(path, { force: true })
    await rm(path + ".__meta__", { force: true })
  }

  async deleteMany(keys: string[], _context?: StoreContext): Promise<void> {
    for (const key of keys) await this.delete(key, _context)
  }
}
