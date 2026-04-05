import { describe, it, expect } from "vitest"
import { validateConfig } from "../../src/config/validate.js"
import { parseConfigJson, loadConfig, saveConfig } from "../../src/config/loader.js"
import type { SyncConfig } from "../../src/config/schema.js"
import { createIsolatedStore } from "../helpers.js"

function validConfig(overrides: Partial<SyncConfig> = {}): SyncConfig {
  return {
    version: 1,
    collections: [
      {
        name: "settings",
        storagePath: "users/{identity}/settings",
        readRoles: ["self"],
        writeRoles: ["self"],
        encryption: "none",
        allowedMimeTypes: ["application/json"],
      },
    ],
    ...overrides,
  }
}

describe("validateConfig", () => {
  it("accepts valid config", () => {
    expect(validateConfig(validConfig())).toEqual([])
  })

  it("rejects duplicate collection names", () => {
    const config = validConfig({
      collections: [
        { name: "a", storagePath: "path1", readRoles: ["public"], writeRoles: ["public"], allowedMimeTypes: ["application/json"] },
        { name: "a", storagePath: "path2", readRoles: ["public"], writeRoles: ["public"], allowedMimeTypes: ["application/json"] },
      ],
    })
    const errors = validateConfig(config)
    expect(errors.some((e) => e.includes("Duplicate collection name"))).toBe(true)
  })

  it("rejects pullOnly + pushOnly", () => {
    const config = validConfig({
      collections: [
        {
          name: "a",
          storagePath: "path1",
          readRoles: ["public"],
          writeRoles: ["public"],
          allowedMimeTypes: ["application/json"],
          pullOnly: true,
          pushOnly: true,
        },
      ],
    })
    const errors = validateConfig(config)
    expect(errors.some((e) => e.includes("both pullOnly and pushOnly"))).toBe(true)
  })

  it("rejects public collection with identity encryption", () => {
    const config = validConfig({
      collections: [
        {
          name: "a",
          storagePath: "users/{identity}/data",
          readRoles: ["public"],
          writeRoles: ["public"],
          encryption: "identity",
          allowedMimeTypes: ["application/json"],
        },
      ],
    })
    const errors = validateConfig(config)
    expect(errors.some((e) => e.includes("public collections must not use"))).toBe(true)
  })

  it("rejects binary collection with server encryption", () => {
    const config = validConfig({
      collections: [
        {
          name: "images",
          storagePath: "images/{identity}",
          readRoles: ["self"],
          writeRoles: ["self"],
          encryption: "server",
          allowedMimeTypes: ["image/*"],
        },
      ],
    })
    const errors = validateConfig(config)
    expect(errors.some((e) => e.includes("binary collections cannot use"))).toBe(true)
  })

  it("rejects binary collection with objectSchema", () => {
    const config = validConfig({
      collections: [
        {
          name: "images",
          storagePath: "images",
          readRoles: ["public"],
          writeRoles: ["public"],
          allowedMimeTypes: ["image/*"],
          objectSchema: { type: "object" },
        },
      ],
    })
    const errors = validateConfig(config)
    expect(errors.some((e) => e.includes("objectSchema"))).toBe(true)
  })

  it("rejects remote collection with template variables", () => {
    const config = validConfig({
      collections: [
        {
          name: "remote",
          storagePath: "data/{identity}",
          readRoles: ["public"],
          writeRoles: ["public"],
          allowedMimeTypes: ["application/json"],
          remote: {
            url: "https://primary.example.com",
            pullPath: "/pull/data",
          },
        },
      ],
    })
    const errors = validateConfig(config)
    expect(errors.some((e) => e.includes("template variables"))).toBe(true)
  })

  it("rejects remote push_through without pushPath", () => {
    const config = validConfig({
      collections: [
        {
          name: "remote",
          storagePath: "data",
          readRoles: ["public"],
          writeRoles: ["public"],
          allowedMimeTypes: ["application/json"],
          remote: {
            url: "https://primary.example.com",
            pullPath: "/pull/data",
            writeMode: "push_through",
          },
        },
      ],
    })
    const errors = validateConfig(config)
    expect(errors.some((e) => e.includes("pushPath"))).toBe(true)
  })

  it("rejects remote webhook without webhookSecret", () => {
    const config = validConfig({
      collections: [
        {
          name: "remote",
          storagePath: "data",
          readRoles: ["public"],
          writeRoles: ["public"],
          allowedMimeTypes: ["application/json"],
          remote: {
            url: "https://primary.example.com",
            pullPath: "/pull/data",
            syncTriggers: ["webhook"],
          },
        },
      ],
    })
    const errors = validateConfig(config)
    expect(errors.some((e) => e.includes("webhookSecret"))).toBe(true)
  })
})

describe("parseConfigJson", () => {
  it("parses valid JSON config", () => {
    const config = parseConfigJson(JSON.stringify(validConfig()))
    expect(config.version).toBe(1)
    expect(config.collections).toHaveLength(1)
  })

  it("rejects invalid version", () => {
    expect(() =>
      parseConfigJson(JSON.stringify({ version: 2, collections: [] })),
    ).toThrow("Unsupported config version")
  })

  it("rejects invalid config", () => {
    const bad = {
      version: 1,
      collections: [
        { name: "a", storagePath: "p", readRoles: [], writeRoles: [], pullOnly: true, pushOnly: true },
      ],
    }
    expect(() => parseConfigJson(JSON.stringify(bad))).toThrow("Invalid config")
  })
})

describe("loadConfig / saveConfig", () => {
  it("returns null when no config stored", async () => {
    const store = createIsolatedStore()
    expect(await loadConfig(store)).toBeNull()
  })

  it("round-trips config through store", async () => {
    const store = createIsolatedStore()
    const config = validConfig()
    await saveConfig(store, config)
    const loaded = await loadConfig(store)
    expect(loaded).toEqual(config)
  })

  it("saveConfig validates before saving", async () => {
    const store = createIsolatedStore()
    const bad: SyncConfig = {
      version: 1,
      collections: [
        { name: "a", storagePath: "p", readRoles: [], writeRoles: [], pullOnly: true, pushOnly: true },
      ],
    }
    await expect(saveConfig(store, bad)).rejects.toThrow("Invalid config")
  })
})
