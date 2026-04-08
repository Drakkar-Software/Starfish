import { describe, it, expect } from "vitest"
import { generateOpenApiSpec } from "../src/openapi.js"
import type { SyncConfig } from "../src/config/schema.js"

describe("generateOpenApiSpec", () => {
  const config: SyncConfig = {
    version: 1,
    collections: [
      {
        name: "settings",
        storagePath: "users/{identity}/settings",
        readRoles: ["self"],
        writeRoles: ["self"],
        encryption: "none",
        maxBodyBytes: 1_000_000,
        allowedMimeTypes: ["application/json"],
      },
      {
        name: "public-config",
        storagePath: "app/config",
        readRoles: ["public"],
        writeRoles: ["admin"],
        encryption: "none",
        maxBodyBytes: 1_000_000,
        allowedMimeTypes: ["application/json"],
      },
    ],
  }

  it("generates valid OpenAPI 3.0 spec", () => {
    const spec = generateOpenApiSpec(config)
    expect(spec["openapi"]).toBe("3.0.3")
    expect((spec["info"] as any).title).toBe("Starfish Sync API")
  })

  it("includes pull and push paths for each collection", () => {
    const spec = generateOpenApiSpec(config)
    const paths = spec["paths"] as Record<string, unknown>
    expect(paths["/pull/users/{identity}/settings"]).toBeDefined()
    expect(paths["/push/users/{identity}/settings"]).toBeDefined()
    expect(paths["/pull/app/config"]).toBeDefined()
    expect(paths["/push/app/config"]).toBeDefined()
  })

  it("includes health endpoint", () => {
    const spec = generateOpenApiSpec(config)
    const paths = spec["paths"] as Record<string, unknown>
    expect(paths["/health"]).toBeDefined()
  })

  it("includes path parameters", () => {
    const spec = generateOpenApiSpec(config)
    const paths = spec["paths"] as Record<string, any>
    const pullOp = paths["/pull/users/{identity}/settings"]["get"]
    const params = pullOp.parameters as any[]
    const identityParam = params.find((p: any) => p.name === "identity")
    expect(identityParam).toBeDefined()
    expect(identityParam.in).toBe("path")
  })

  it("includes component schemas", () => {
    const spec = generateOpenApiSpec(config)
    const schemas = (spec["components"] as any).schemas
    expect(schemas.PullResponse).toBeDefined()
    expect(schemas.PushRequest).toBeDefined()
    expect(schemas.PushResponse).toBeDefined()
    expect(schemas.ErrorResponse).toBeDefined()
  })

  it("supports custom title and server URL", () => {
    const spec = generateOpenApiSpec(config, {
      title: "My API",
      version: "2.0.0",
      serverUrl: "https://api.example.com",
    })
    expect((spec["info"] as any).title).toBe("My API")
    expect((spec["info"] as any).version).toBe("2.0.0")
    expect((spec["servers"] as any)[0].url).toBe("https://api.example.com")
  })

  it("respects pullOnly/pushOnly", () => {
    const spec = generateOpenApiSpec({
      version: 1,
      collections: [
        {
          name: "readonly",
          storagePath: "readonly",
          readRoles: ["public"],
          writeRoles: ["admin"],
          encryption: "none",
          maxBodyBytes: 1000,
          allowedMimeTypes: ["application/json"],
          pullOnly: true,
        },
      ],
    })
    const paths = spec["paths"] as Record<string, unknown>
    expect(paths["/pull/readonly"]).toBeDefined()
    expect(paths["/push/readonly"]).toBeUndefined()
  })
})
