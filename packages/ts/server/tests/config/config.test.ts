import { describe, it, expect } from "vitest"
import { validateConfig, collectConfigWarnings } from "../../src/config/validate.js"
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
    encryption: "none",
    maxBodyBytes: 1_000_000,
    allowedMimeTypes: ["application/json"],
    ...overrides,
  }
}

function makeConfig(collections: CollectionConfig[] = [makeCol()]): SyncConfig {
  return { version: 1, collections }
}

describe("collectConfigWarnings (non-fatal)", () => {
  it("returns no warnings for a clean config", () => {
    const cfg = makeConfig([makeCol({ name: "notes", readRoles: ["cap:read:notes"], writeRoles: ["cap:write:notes"] })])
    expect(collectConfigWarnings(cfg)).toEqual([])
  })

  it("warns when writeRoles contains 'public' (anonymous writes)", () => {
    const cfg = makeConfig([makeCol({ name: "posts", readRoles: ["public"], writeRoles: ["public"] })])
    const warnings = collectConfigWarnings(cfg)
    expect(warnings.length).toBe(1)
    expect(warnings[0]).toMatch(/writeRoles contains "public"/)
  })

  it("warns when a collection references another collection's cap role", () => {
    // Copy-paste typo: 'secrets' lists 'cap:read:notes'.
    const cfg = makeConfig([
      makeCol({ name: "secrets", readRoles: ["cap:read:notes"], writeRoles: ["cap:write:secrets"] }),
    ])
    const warnings = collectConfigWarnings(cfg)
    expect(warnings.length).toBe(1)
    expect(warnings[0]).toMatch(/cap role scoped to a different collection \("notes"\)/)
  })

  it("does not warn for the collection's own cap role or a '*' wildcard", () => {
    const cfg = makeConfig([
      makeCol({ name: "notes", readRoles: ["cap:read:notes", "cap:read:*"], writeRoles: ["cap:write:notes"] }),
    ])
    expect(collectConfigWarnings(cfg)).toEqual([])
  })

  it("warns when a collection uses 'self' but its storagePath has no {identity} segment", () => {
    const cfg = makeConfig([
      makeCol({ name: "shared", storagePath: "rooms/{owner}/notes", readRoles: ["self"], writeRoles: ["self"] }),
    ])
    const warnings = collectConfigWarnings(cfg)
    expect(warnings.some((w) => /"self" role.*\{identity\}/.test(w))).toBe(true)
  })

  it("does not warn for an {identity} storagePath", () => {
    const cfg = makeConfig([
      makeCol({ name: "mine", storagePath: "users/{identity}/notes", readRoles: ["self"], writeRoles: ["self"] }),
    ])
    expect(collectConfigWarnings(cfg)).toEqual([])
  })
})

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

  it("accepts a listable collection whose storagePath has a trailing slash (parity with Python)", () => {
    // "logs/{day}/" — the last meaningful segment is the "{day}" param. The TS
    // validator used to read "" after the trailing slash and reject it, while
    // the Python validator (rstrip) accepted it; both now agree.
    const errors = validateConfig(
      makeConfig([
        makeCol({
          name: "logs",
          storagePath: "logs/{day}/",
          listable: true,
          readRoles: ["cap:read:logs"],
          writeRoles: ["cap:write:logs"],
        }),
      ]),
    )
    expect(errors).toEqual([])
  })

  it("detects empty allowedMimeTypes", () => {
    const errors = validateConfig(
      makeConfig([makeCol({ allowedMimeTypes: [] })]),
    )
    expect(errors.some((e) => e.includes("allowedMimeTypes"))).toBe(true)
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

  it("rejects rootOnly combined with a public readRole", () => {
    const errors = validateConfig(
      makeConfig([makeCol({ name: "secret", rootOnly: true, readRoles: ["public"], writeRoles: ["self"] })]),
    )
    expect(errors.some((e) => e.includes("rootOnly cannot be combined"))).toBe(true)
  })

  it("rejects rootOnly combined with a public writeRole", () => {
    const errors = validateConfig(
      makeConfig([makeCol({ name: "secret", rootOnly: true, readRoles: ["cap:read:secret"], writeRoles: ["public"] })]),
    )
    expect(errors.some((e) => e.includes("rootOnly cannot be combined"))).toBe(true)
  })

  it("accepts rootOnly with non-public roles", () => {
    const errors = validateConfig(
      makeConfig([makeCol({ name: "secret", rootOnly: true, readRoles: ["cap:read:secret"], writeRoles: ["cap:write:secret"] })]),
    )
    expect(errors).toEqual([])
  })

  it("rejects non-positive appendOnly.maxPullLimit / maxCheckpointAgeMs", () => {
    for (const bad of [{ maxPullLimit: 0 }, { maxPullLimit: -1 }, { maxCheckpointAgeMs: 0 }, { maxCheckpointAgeMs: 1.5 }]) {
      const errors = validateConfig(
        makeConfig([makeCol({ name: "ev", storagePath: "ev", appendOnly: { type: "by_timestamp", ...bad } })]),
      )
      expect(errors.some((e) => e.includes("positive integer"))).toBe(true)
    }
  })

  it("rejects appendOnly.maxPullLimit / maxCheckpointAgeMs with persist=false", () => {
    const errors = validateConfig(
      makeConfig([makeCol({ name: "ev", storagePath: "ev", appendOnly: { type: "by_timestamp", persist: false, maxPullLimit: 10, maxCheckpointAgeMs: 1000 } })]),
    )
    expect(errors.some((e) => e.includes("maxPullLimit requires persist=true"))).toBe(true)
    expect(errors.some((e) => e.includes("maxCheckpointAgeMs requires persist=true"))).toBe(true)
  })

  it("accepts valid appendOnly bound config (allowFull / maxPullLimit / maxCheckpointAgeMs)", () => {
    const errors = validateConfig(
      makeConfig([makeCol({ name: "ev", storagePath: "ev", appendOnly: { type: "by_timestamp", allowFull: false, maxPullLimit: 100, maxCheckpointAgeMs: 86_400_000 } })]),
    )
    expect(errors).toEqual([])
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
    for (const name of ["pull", "push", "list", "health", "batch"]) {
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
          encryption: "none",
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

  it("preserves rootOnly / listable / restrictions through a JSON round-trip (fail-closed authz)", () => {
    // These authorization controls were silently dropped by the hand-written
    // caster, so a JSON config enforced them on Python but not on TS. They must
    // survive parse so the two servers make identical access decisions.
    const restriction = { mode: "deny" as const, identities: ["deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"] }
    const raw = JSON.stringify({
      version: 1,
      restrictions: [restriction],
      collections: [
        {
          name: "admin",
          storagePath: "admin/{identity}/{item}",
          readRoles: ["cap:read:admin"],
          writeRoles: ["cap:write:admin"],
          encryption: "none",
          maxBodyBytes: 1000000,
          rootOnly: true,
          listable: true,
          restrictions: [restriction],
        },
      ],
      namespaces: {
        tenantA: {
          restrictions: [restriction],
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
    const col = config.collections[0]!
    expect(col.rootOnly).toBe(true)
    expect(col.listable).toBe(true)
    expect(col.restrictions).toEqual([restriction])
    expect(config.restrictions).toEqual([restriction])
    expect(config.namespaces?.["tenantA"]?.restrictions).toEqual([restriction])
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
