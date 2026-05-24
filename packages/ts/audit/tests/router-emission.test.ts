import { describe, it, expect } from "vitest"
import { createSyncRouter, MemoryObjectStore } from "@drakkar.software/starfish-server"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { webcrypto } from "node:crypto"
import { createCallbackAuditLogger } from "../src/audit.js"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

describe("audit logging integration", () => {
  it("records pull events to audit logger", async () => {
    const entries: any[] = []
    const auditLogger = createCallbackAuditLogger((e) => { entries.push(e) })
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
      store,
      config: {
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
        ],
      },
      roleResolver: async () => ({ identity: "user-1", roles: ["self"] }),
      auditLogger,
    })

    await app.request("/pull/users/user-1/settings")
    expect(entries).toHaveLength(1)
    expect(entries[0].action).toBe("pull")
    expect(entries[0].collection).toBe("settings")
    expect(entries[0].identity).toBe("user-1")
    expect(entries[0].success).toBe(true)
  })

  it("records push events to audit logger", async () => {
    const entries: any[] = []
    const auditLogger = createCallbackAuditLogger((e) => { entries.push(e) })
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
      store,
      config: {
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
        ],
      },
      roleResolver: async () => ({ identity: "user-1", roles: ["self"] }),
      auditLogger,
    })

    await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })
    expect(entries).toHaveLength(1)
    expect(entries[0].action).toBe("push")
    expect(entries[0].success).toBe(true)
  })

  function appWith(auditLogger: any) {
    const store = new MemoryObjectStore(new Map())
    return createSyncRouter({
      store,
      config: {
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
        ],
      },
      roleResolver: async () => ({ identity: "user-1", roles: ["self"] }),
      auditLogger,
    })
  }

  it("awaits an async audit logger before returning the push response", async () => {
    // The server `await`s opts.auditLogger.record(...) (route-builder.ts), so an
    // async logger's write completes before the response is returned and a rejecting
    // logger surfaces rather than becoming an unhandled rejection. Both languages
    // agree; see test_audit_router.py for the Python twin.
    let auditCompleted = false
    const auditLogger = createCallbackAuditLogger(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0))
      auditCompleted = true
    })
    const app = appWith(auditLogger)
    await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })
    expect(auditCompleted).toBe(true)
  })
})
