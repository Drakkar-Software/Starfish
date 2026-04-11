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

  const nsConfig: SyncConfig = {
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
            maxBodyBytes: 1000,
            allowedMimeTypes: ["application/json"],
          },
        ],
      },
    },
  }

  it("generates namespaced paths", () => {
    const spec = generateOpenApiSpec(nsConfig)
    const paths = spec["paths"] as Record<string, unknown>
    expect(paths["/tenantA/pull/users/{identity}/settings"]).toBeDefined()
    expect(paths["/tenantA/push/users/{identity}/settings"]).toBeDefined()
  })

  it("includes namespace batch/pull path in spec", () => {
    const spec = generateOpenApiSpec(nsConfig)
    const paths = spec["paths"] as Record<string, unknown>
    expect(paths["/tenantA/batch/pull"]).toBeDefined()
  })

  it("uses -- separator in operationIds to avoid collisions with underscore-named namespaces", () => {
    // Without the -- separator, namespace "a_b" + collection "c" would produce "pull_a_b_c",
    // which is the same as namespace "a" + collection "b_c". The -- separator prevents this.
    const spec = generateOpenApiSpec({
      version: 1,
      collections: [
        {
          name: "settings",
          storagePath: "app/settings",
          readRoles: ["public"],
          writeRoles: ["admin"],
          encryption: "none",
          maxBodyBytes: 1000,
          allowedMimeTypes: ["application/json"],
        },
      ],
      namespaces: {
        tenant_a: {
          collections: [
            {
              name: "b_settings",
              storagePath: "users/{identity}/settings",
              readRoles: ["self"],
              writeRoles: ["self"],
              encryption: "none",
              maxBodyBytes: 1000,
              allowedMimeTypes: ["application/json"],
            },
          ],
        },
        tenant: {
          collections: [
            {
              name: "a_b_settings",
              storagePath: "users/{identity}/other",
              readRoles: ["self"],
              writeRoles: ["self"],
              encryption: "none",
              maxBodyBytes: 1000,
              allowedMimeTypes: ["application/json"],
            },
          ],
        },
      },
    })
    const paths = spec["paths"] as Record<string, any>
    const id1 = paths["/tenant_a/pull/users/{identity}/settings"]["get"].operationId
    const id2 = paths["/tenant/pull/users/{identity}/other"]["get"].operationId
    // Both would collide under underscore separator: "pull_tenant_a_b_settings"
    expect(id1).toBe("pull--tenant_a--b_settings")
    expect(id2).toBe("pull--tenant--a_b_settings")
    // They must be distinct
    expect(id1).not.toBe(id2)
    // Root collection uses legacy _ format for backward compatibility
    expect(paths["/pull/app/settings"]["get"].operationId).toBe("pull_settings")
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
