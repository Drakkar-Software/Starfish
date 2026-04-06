import { describe, it, expect, vi } from "vitest"
import { ValidationError, createSchemaValidator } from "../src/validate.js"
import { StarfishClient } from "../src/client.js"
import { SyncManager } from "../src/sync.js"

function mockClient() {
  return {
    pull: vi.fn(async () => ({
      data: { key: "value" },
      hash: "abc123",
      timestamp: 1000,
    })),
    push: vi.fn(async () => ({
      hash: "def456",
      timestamp: 2000,
    })),
  } as unknown as StarfishClient
}

describe("ValidationError", () => {
  it("includes error messages", () => {
    const err = new ValidationError(["field required", "type mismatch"])
    expect(err.errors).toEqual(["field required", "type mismatch"])
    expect(err.message).toContain("field required")
    expect(err.message).toContain("type mismatch")
    expect(err.name).toBe("ValidationError")
  })
})

describe("createSchemaValidator", () => {
  it("returns true for valid data", () => {
    const mockAjv = {
      compile: () => {
        const fn = ((data: unknown) => typeof (data as Record<string, unknown>).name === "string") as { (data: unknown): boolean; errors?: unknown }
        fn.errors = null
        return fn
      },
      errorsText: () => "error",
    }

    const validator = createSchemaValidator(mockAjv, {})
    expect(validator({ name: "test" })).toBe(true)
  })

  it("returns error messages for invalid data", () => {
    const mockAjv = {
      compile: () => {
        const fn = (() => false) as { (data: unknown): boolean; errors?: unknown }
        fn.errors = [{ message: "bad" }]
        return fn
      },
      errorsText: () => "data/name must be string",
    }

    const validator = createSchemaValidator(mockAjv, {})
    const result = validator({ name: 123 })
    expect(result).toEqual(["data/name must be string"])
  })
})

describe("SyncManager validate option", () => {
  it("blocks push when validation fails", async () => {
    const sync = new SyncManager({
      client: mockClient(),
      pullPath: "/pull/test",
      pushPath: "/push/test",
      validate: (data) => {
        if (!data.name) return ["name is required"]
        return true
      },
    })

    await expect(sync.push({})).rejects.toThrow(ValidationError)
    await expect(sync.push({})).rejects.toThrow("name is required")
  })

  it("allows push when validation passes", async () => {
    const client = mockClient()
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      validate: (data) => {
        if (!data.name) return ["name is required"]
        return true
      },
    })

    const result = await sync.push({ name: "valid" })
    expect(result.hash).toBe("def456")
    expect(client.push).toHaveBeenCalled()
  })

  it("validates before any network call", async () => {
    const client = mockClient()
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      validate: () => ["always fails"],
    })

    await expect(sync.push({ x: 1 })).rejects.toThrow(ValidationError)
    expect(client.push).not.toHaveBeenCalled()
  })

  it("works without validate option", async () => {
    const sync = new SyncManager({
      client: mockClient(),
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })

    await expect(sync.push({ anything: true })).resolves.toBeDefined()
  })
})
