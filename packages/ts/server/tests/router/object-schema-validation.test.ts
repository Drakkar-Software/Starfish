/**
 * objectSchema validation must FAIL CLOSED.
 *
 * When a collection declares an `objectSchema` but no JSON Schema validator can be
 * resolved (a runtime without `require()` — ESM/Workers/Deno — and no `setAjv()`
 * call), the write must be REJECTED rather than stored unvalidated. Silently
 * skipping validation would let a payload that violates the schema through.
 */

import { describe, it, expect, afterEach } from "vitest"
import { webcrypto } from "node:crypto"
import Ajv from "ajv"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { createSyncRouter, setAjv, type SyncRouterOptions, type AuthResult } from "../../src/router/route-builder.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import type { SyncConfig, CollectionConfig } from "../../src/config/schema.js"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

function schemaCol(): CollectionConfig {
  return {
    name: "settings",
    storagePath: "users/{identity}/settings",
    readRoles: ["self"],
    writeRoles: ["self"],
    encryption: "none",
    maxBodyBytes: 65536,
    allowedMimeTypes: ["application/json"],
    objectSchema: {
      type: "object",
      properties: { n: { type: "number" } },
      required: ["n"],
      additionalProperties: false,
    },
  } as CollectionConfig
}

function makeRouter() {
  const store = new MemoryObjectStore(new Map())
  const config: SyncConfig = { version: 1, collections: [schemaCol()] }
  const opts: SyncRouterOptions = {
    store,
    config,
    roleResolver: async (): Promise<AuthResult> => ({ identity: "user-1", roles: ["self"] }),
  }
  return createSyncRouter(opts)
}

function push(app: ReturnType<typeof createSyncRouter>, data: unknown) {
  return app.request("/push/users/user-1/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ data, baseHash: null }),
  })
}

// Reset the module-level validator between tests so each test controls its own state.
afterEach(() => setAjv(null))

describe("objectSchema validation fails closed when no validator is available", () => {
  it("rejects the write (500) instead of storing it unvalidated", async () => {
    const savedRequire = (globalThis as { require?: unknown }).require
    ;(globalThis as { require?: unknown }).require = undefined
    setAjv(null)
    try {
      const app = makeRouter()
      // `data` is schema-VALID, so a 500 can only come from the missing validator
      // (not from a validation failure): the write is refused, never stored.
      const res = await push(app, { n: 1 })
      expect(res.status).toBe(500)
    } finally {
      ;(globalThis as { require?: unknown }).require = savedRequire
      setAjv(null)
    }
  })
})

describe("objectSchema validation with an injected validator still enforces the schema", () => {
  it("rejects a schema violation (400) and accepts valid data (200)", async () => {
    setAjv(new Ajv())
    const app = makeRouter()
    expect((await push(app, { n: "not-a-number" })).status).toBe(400)
    expect((await push(app, { n: 5 })).status).toBe(200)
  })
})
