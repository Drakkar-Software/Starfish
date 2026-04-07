import { describe, it, expect } from "vitest"
import { createMigrator } from "../src/migrate.js"

describe("createMigrator", () => {
  it("passes through data at current version unchanged", () => {
    const migrate = createMigrator({
      currentVersion: 2,
      migrations: {
        1: (d) => ({ ...d, migrated: true }),
      },
    })

    const data = { _schemaVersion: 2, name: "test" }
    expect(migrate(data)).toEqual(data)
  })

  it("applies a single migration", () => {
    const migrate = createMigrator({
      currentVersion: 2,
      migrations: {
        1: (d) => ({ ...d, newField: "added" }),
      },
    })

    const result = migrate({ _schemaVersion: 1, name: "test" })
    expect(result).toEqual({
      _schemaVersion: 2,
      name: "test",
      newField: "added",
    })
  })

  it("applies a chain of migrations", () => {
    const migrate = createMigrator({
      currentVersion: 4,
      migrations: {
        1: (d) => ({ ...d, v2: true }),
        2: (d) => ({ ...d, v3: true }),
        3: (d) => ({ ...d, v4: true }),
      },
    })

    const result = migrate({ _schemaVersion: 1, old: "data" })
    expect(result).toEqual({
      _schemaVersion: 4,
      old: "data",
      v2: true,
      v3: true,
      v4: true,
    })
  })

  it("defaults missing _schemaVersion to 1", () => {
    const migrate = createMigrator({
      currentVersion: 2,
      migrations: {
        1: (d) => ({ ...d, upgraded: true }),
      },
    })

    const result = migrate({ legacy: "data" })
    expect(result).toEqual({
      _schemaVersion: 2,
      legacy: "data",
      upgraded: true,
    })
  })

  it("throws on forward-incompatible version", () => {
    const migrate = createMigrator({
      currentVersion: 2,
      migrations: {
        1: (d) => ({ ...d }),
      },
    })

    expect(() => migrate({ _schemaVersion: 5 })).toThrow(
      "Document schema version 5 is newer than app version 2",
    )
  })

  it("throws on missing migration step at creation time", () => {
    expect(() => createMigrator({
      currentVersion: 3,
      migrations: {
        // Missing migration for version 1 -> 2
        2: (d) => ({ ...d, v3: true }),
      },
    })).toThrow(
      "Missing migration for version 1 -> 2",
    )
  })

  it("each migration receives the output of the previous one", () => {
    const migrate = createMigrator({
      currentVersion: 3,
      migrations: {
        1: (d) => ({ ...d, step1: d.count as number + 1, count: (d.count as number) + 1 }),
        2: (d) => ({ ...d, step2: d.count as number + 1, count: (d.count as number) + 1 }),
      },
    })

    const result = migrate({ _schemaVersion: 1, count: 0 })
    expect(result.step1).toBe(1)
    expect(result.step2).toBe(2)
    expect(result.count).toBe(2)
  })
})
