import { describe, it, expect } from "vitest"
import { validateConfig } from "../../src/config/validate.js"
import { parseConfigJson, loadConfig, saveConfig } from "../../src/config/loader.js"
import { createIsolatedStore } from "../helpers.js"
import type { SyncConfig, CollectionConfig } from "../../src/config/schema.js"

function makeNsCol(overrides: Partial<CollectionConfig> = {}): CollectionConfig {
  return {
    name: "settings",
    storagePath: "users/{identity}/settings",
    readRoles: ["self"],
    writeRoles: ["self"],
    encryption: "none",
    maxBodyBytes: 1_000_000,
    allowedMimeTypes: ["application/json"],
    ...overrides,
  }
}

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

  it("group encryption is valid on authenticated collection", () => {
    const errors = validateConfig(
      makeConfig([makeCol({ readRoles: ["group-member"], writeRoles: ["group-member"], encryption: "group" })]),
    )
    expect(errors).toEqual([])
  })

  it("detects public + group encryption conflict", () => {
    const errors = validateConfig(
      makeConfig([makeCol({ readRoles: ["public"], encryption: "group" })]),
    )
    expect(errors.some((e) => e.includes("public collections cannot use") && e.includes("group"))).toBe(true)
  })

  it("detects binary collection with group encryption", () => {
    const errors = validateConfig(
      makeConfig([makeCol({ allowedMimeTypes: ["image/png"], encryption: "group" })]),
    )
    expect(errors.some((e) => e.includes("binary collections cannot use"))).toBe(true)
  })

  it("detects remote collection with group encryption", () => {
    const errors = validateConfig(
      makeConfig([
        makeCol({
          storagePath: "data/shared",
          encryption: "group",
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
    expect(errors.some((e) => e.includes("group") && e.includes("remote"))).toBe(true)
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

describe("validateConfig — namespaces", () => {
  it("valid config with namespaces returns no errors", () => {
    const config: SyncConfig = {
      version: 1,
      collections: [],
      namespaces: {
        tenantA: { collections: [makeNsCol()] },
        tenantB: { collections: [makeNsCol()] },
      },
    }
    expect(validateConfig(config)).toEqual([])
  })

  it("same collection name in different namespaces is valid", () => {
    const config: SyncConfig = {
      version: 1,
      collections: [],
      namespaces: {
        tenantA: { collections: [makeNsCol({ name: "settings" })] },
        tenantB: { collections: [makeNsCol({ name: "settings" })] },
      },
    }
    expect(validateConfig(config)).toEqual([])
  })

  it("same collection name in root and namespace is valid", () => {
    const config: SyncConfig = {
      version: 1,
      collections: [makeNsCol({ name: "settings" })],
      namespaces: {
        tenantA: { collections: [makeNsCol({ name: "settings" })] },
      },
    }
    expect(validateConfig(config)).toEqual([])
  })

  it("duplicate name within a namespace produces error", () => {
    const config: SyncConfig = {
      version: 1,
      collections: [],
      namespaces: {
        tenantA: { collections: [makeNsCol(), makeNsCol()] },
      },
    }
    const errors = validateConfig(config)
    expect(errors).toHaveLength(1)
    expect(errors[0]).toContain("Namespace \"tenantA\"")
    expect(errors[0]).toContain("Duplicate")
  })

  it("detects invalid namespace name characters", () => {
    const config: SyncConfig = {
      version: 1,
      collections: [],
      namespaces: {
        "bad name!": { collections: [makeNsCol()] },
      },
    }
    const errors = validateConfig(config)
    expect(errors.some((e) => e.includes("letters, digits, hyphens"))).toBe(true)
  })

  it("detects reserved namespace names", () => {
    for (const name of ["pull", "push", "health", "batch"]) {
      const config: SyncConfig = {
        version: 1,
        collections: [],
        namespaces: {
          [name]: { collections: [makeNsCol()] },
        },
      }
      const errors = validateConfig(config)
      expect(errors.some((e) => e.includes("reserved"))).toBe(true)
    }
  })

  it("propagates collection errors with namespace scope label", () => {
    const config: SyncConfig = {
      version: 1,
      collections: [],
      namespaces: {
        tenantA: { collections: [makeNsCol({ storagePath: "/bad" })] },
      },
    }
    const errors = validateConfig(config)
    expect(errors.some((e) => e.includes("Namespace \"tenantA\""))).toBe(true)
    expect(errors.some((e) => e.includes("must not start with /"))).toBe(true)
  })

  it("hyphens and underscores are valid namespace names", () => {
    const config: SyncConfig = {
      version: 1,
      collections: [],
      namespaces: {
        "tenant-a": { collections: [makeNsCol()] },
        tenant_b: { collections: [makeNsCol()] },
      },
    }
    expect(validateConfig(config)).toEqual([])
  })

  it("empty namespace collections produces error", () => {
    const config: SyncConfig = {
      version: 1,
      collections: [],
      namespaces: { tenantA: { collections: [] } },
    }
    const errors = validateConfig(config)
    expect(errors.some((e) => e.includes("at least one collection"))).toBe(true)
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

  it("parses config with namespaces", () => {
    const raw = JSON.stringify({
      version: 1,
      collections: [],
      namespaces: {
        tenantA: {
          collections: [
            {
              name: "settings",
              storagePath: "users/{identity}/settings",
              readRoles: ["self"],
              writeRoles: ["self"],
              encryption: "none",
              maxBodyBytes: 1000000,
            },
          ],
        },
      },
    })
    const config = parseConfigJson(raw)
    expect(config.namespaces?.["tenantA"]?.collections[0]?.name).toBe("settings")
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

  it("throws on reserved namespace name", () => {
    const raw = JSON.stringify({
      version: 1,
      collections: [],
      namespaces: {
        push: {
          collections: [
            {
              name: "settings",
              storagePath: "users/{identity}/settings",
              readRoles: ["self"],
              writeRoles: ["self"],
              encryption: "none",
              maxBodyBytes: 1000000,
            },
          ],
        },
      },
    })
    expect(() => parseConfigJson(raw)).toThrow("Invalid sync config")
  })

  it("throws with StartupError when namespace value is null", () => {
    const raw = JSON.stringify({
      version: 1,
      collections: [],
      namespaces: { tenantA: null },
    })
    expect(() => parseConfigJson(raw)).toThrow("Invalid sync config")
  })

  it("throws with StartupError when namespace value is a non-object", () => {
    const raw = JSON.stringify({
      version: 1,
      collections: [],
      namespaces: { tenantA: "oops" },
    })
    // Non-object namespace silently becomes empty collections, caught by empty-namespace validation
    expect(() => parseConfigJson(raw)).toThrow("Invalid sync config")
  })

  it("parses ttlMs and fieldPermissions from collection JSON", () => {
    const raw = JSON.stringify({
      version: 1,
      collections: [
        {
          name: "settings",
          storagePath: "users/{identity}/settings",
          readRoles: ["self"],
          writeRoles: ["self"],
          encryption: "none",
          maxBodyBytes: 1000000,
          ttlMs: 86400000,
          fieldPermissions: { email: { readRoles: ["admin"] } },
        },
      ],
    })
    const config = parseConfigJson(raw)
    expect(config.collections[0]!.ttlMs).toBe(86400000)
    expect(config.collections[0]!.fieldPermissions?.["email"]?.readRoles).toEqual(["admin"])
  })

  it("parses ttlMs and fieldPermissions in namespace collections", () => {
    const raw = JSON.stringify({
      version: 1,
      collections: [],
      namespaces: {
        tenantA: {
          collections: [
            {
              name: "settings",
              storagePath: "users/{identity}/settings",
              readRoles: ["self"],
              writeRoles: ["self"],
              encryption: "none",
              maxBodyBytes: 1000000,
              ttlMs: 3600000,
              fieldPermissions: { secret: { writeRoles: ["admin"] } },
            },
          ],
        },
      },
    })
    const config = parseConfigJson(raw)
    const col = config.namespaces?.["tenantA"]?.collections[0]
    expect(col?.ttlMs).toBe(3600000)
    expect(col?.fieldPermissions?.["secret"]?.writeRoles).toEqual(["admin"])
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

  it("round-trips namespace config", async () => {
    const store = createIsolatedStore()
    const config: SyncConfig = {
      version: 1,
      collections: [],
      namespaces: {
        tenantA: { collections: [makeNsCol()] },
      },
    }
    await saveConfig(store, config)
    const loaded = await loadConfig(store)
    expect(loaded).not.toBeNull()
    expect(loaded!.namespaces?.["tenantA"]?.collections[0]?.name).toBe("settings")
  })
})
