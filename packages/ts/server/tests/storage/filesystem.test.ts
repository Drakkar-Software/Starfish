import { describe, it, expect, beforeEach } from "vitest"
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"
import { FilesystemObjectStore } from "../../src/storage/filesystem.js"

describe("FilesystemObjectStore", () => {
  let baseDir: string
  let store: FilesystemObjectStore

  beforeEach(() => {
    baseDir = fs.mkdtempSync(path.join(os.tmpdir(), "starfish-fs-test-"))
    store = new FilesystemObjectStore({ baseDir })
  })

  it("returns null for missing key", async () => {
    expect(await store.getString("nope")).toBeNull()
  })

  it("put and get round-trip", async () => {
    await store.put("test.json", '{"hello":"world"}')
    expect(await store.getString("test.json")).toBe('{"hello":"world"}')
  })

  it("overwrites existing key", async () => {
    await store.put("k", "v1")
    await store.put("k", "v2")
    expect(await store.getString("k")).toBe("v2")
  })

  it("deletes key (idempotent)", async () => {
    await store.put("k", "v")
    await store.delete("k")
    expect(await store.getString("k")).toBeNull()
    await store.delete("k") // no throw
  })

  it("deletes many keys", async () => {
    await store.put("a", "1")
    await store.put("b", "2")
    await store.deleteMany(["a", "b"])
    expect(await store.getString("a")).toBeNull()
    expect(await store.getString("b")).toBeNull()
  })

  it("rejects path traversal", async () => {
    await expect(store.getString("../etc/passwd")).rejects.toThrow("Invalid key")
  })

  it("rejects keys with spaces", async () => {
    await expect(store.getString("bad key")).rejects.toThrow("Invalid key")
  })

  it("binary put/get round-trip", async () => {
    const data = Buffer.from("binary content")
    await store.putBytes("img.png", data, { contentType: "image/png" })
    const result = await store.getBytes("img.png")
    expect(result).not.toBeNull()
    expect(result!.contentType).toBe("image/png")
    expect(result!.data.toString()).toBe("binary content")
  })
})
