import { describe, it, expect } from "vitest"
import { validateConfig } from "../../src/config/validate.js"
import { parseConfigJson, loadConfig, saveConfig } from "../../src/config/loader.js"
import { createIsolatedStore } from "../helpers.js"
import type { SyncConfig, CollectionConfig } from "../../src/config/schema.js"

function makeCol(overrides: Partial<CollectionConfig> = {}): CollectionConfig {
  return {
    name: "test",
    storagePath: "users/{identity}/settings",
    readRoles: ["self"],
    writeRoles: ["self"],
    encryption: "identity",
    maxBodyBytes: 1_000_000,
    allowedMimeTypes: ["application/json"],
    ...overrides,
  }
}

function makeConfig(collections: CollectionConfig[] = [makeCol()]): SyncConfig {
  return { version: 1, collections }
}

describe("validateConfig", () => {
  it("valid config returns no errors", () => {
    expect(validateConfig(makeConfig())).toEqual([])
  })

  it("detects duplicate names", () => {
    const errors = validateConfig(makeConfig([makeCol(), makeCol()]))
    expect(errors).toHaveLength(1)
    expect(errors[0]).toContain("Duplicate")
  })

  it("detects storagePath starting with /", () => {
    const errors = validateConfig(makeConfig([makeCol({ storagePath: "/bad" })]))
    expect(errors.some((e) => e.includes("must not start with /"))).toBe(true)
  })

  it("detects pullOnly + pushOnly conflict", () => {
    const errors = validateConfig(
      makeConfig([makeCol({ pullOnly: true, pushOnly: true })]),
    )
    expect(errors.some((e) => e.includes("pullOnly and pushOnly"))).toBe(true)
  })

  it("detects public + identity encryption conflict", () => {
    const errors = validateConfig(
      makeConfig([makeCol({ readRoles: ["public"], encryption: "identity" })]),
    )
    expect(errors.some((e) => e.includes("public collections"))).toBe(true)
  })

  it("detects bundled without identity encryption", () => {
    const errors = validateConfig(
      makeConfig([makeCol({ bundle: "grp", encryption: "none" })]),
    )
    expect(errors.some((e) => e.includes("bundled collections must use"))).toBe(true)
  })

  it("detects empty allowedMimeTypes", () => {
    const errors = validateConfig(
      makeConfig([makeCol({ allowedMimeTypes: [] })]),
    )
    expect(errors.some((e) => e.includes("allowedMimeTypes"))).toBe(true)
  })

  it("detects binary collection with identity encryption", () => {
    const errors = validateConfig(
      makeConfig([
        makeCol({
          allowedMimeTypes: ["image/png"],
          encryption: "identity",
        }),
      ]),
    )
    expect(errors.some((e) => e.includes("binary collections cannot use"))).toBe(true)
  })

  it("detects remote collection with template storagePath", () => {
    const errors = validateConfig(
      makeConfig([
        makeCol({
          storagePath: "users/{identity}/data",
          remote: {
            url: "https://primary.example.com",
            pullPath: "/pull/data",
            intervalMs: 60000,
            headers: {},
            writeMode: "pull_only",
            syncTriggers: ["scheduled"],
          },
        }),
      ]),
    )
    expect(errors.some((e) => e.includes("static storagePath"))).toBe(true)
  })

  it("detects bundle storagePath mismatch", () => {
    const errors = validateConfig(
      makeConfig([
        makeCol({ name: "a", bundle: "grp", storagePath: "users/{identity}/settings" }),
        makeCol({ name: "b", bundle: "grp", storagePath: "users/{identity}/other" }),
      ]),
    )
    expect(errors.some((e) => e.includes("same storagePath"))).toBe(true)
  })
})

describe("parseConfigJson", () => {
  it("parses valid config", () => {
    const raw = JSON.stringify({
      version: 1,
      collections: [
        {
          name: "test",
          storagePath: "users/{identity}/settings",
          readRoles: ["self"],
          writeRoles: ["self"],
          encryption: "identity",
          maxBodyBytes: 1000000,
        },
      ],
    })
    const config = parseConfigJson(raw)
    expect(config.version).toBe(1)
    expect(config.collections).toHaveLength(1)
    expect(config.collections[0]!.name).toBe("test")
    expect(config.collections[0]!.allowedMimeTypes).toEqual(["application/json"])
  })

  it("throws on invalid config", () => {
    const raw = JSON.stringify({
      version: 1,
      collections: [
        {
          name: "test",
          storagePath: "/bad",
          readRoles: ["self"],
          writeRoles: ["self"],
          encryption: "none",
          maxBodyBytes: 1000000,
        },
      ],
    })
    expect(() => parseConfigJson(raw)).toThrow("Invalid sync config")
  })
})

describe("loadConfig / saveConfig", () => {
  it("round-trip through store", async () => {
    const store = createIsolatedStore()
    const config = makeConfig()
    await saveConfig(store, config)
    const loaded = await loadConfig(store)
    expect(loaded).not.toBeNull()
    expect(loaded!.collections[0]!.name).toBe("test")
  })

  it("returns null for missing config", async () => {
    const store = createIsolatedStore()
    expect(await loadConfig(store)).toBeNull()
  })
})
