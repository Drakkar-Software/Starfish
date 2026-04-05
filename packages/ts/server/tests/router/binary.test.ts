import { describe, it, expect } from "vitest"
import { createSyncRouter, type AuthResult } from "../../src/router/route_builder.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import type { SyncConfig } from "../../src/config/schema.js"

function buildBinaryApp() {
  const store = new MemoryObjectStore({ data: {} })
  const config: SyncConfig = {
    version: 1,
    collections: [
      {
        name: "images",
        storagePath: "images/{identity}",
        readRoles: ["public"],
        writeRoles: ["user"],
        allowedMimeTypes: ["image/*"],
        maxBodyBytes: 50_000,
      },
    ],
  }
  const roleResolver = async (request: Request): Promise<AuthResult> => {
    const auth = request.headers.get("authorization")
    if (!auth) throw new Error("No auth")
    return { identity: auth, roles: ["user"] }
  }
  return { app: createSyncRouter({ store, config, roleResolver }), store }
}

describe("binary collections", () => {
  it("push/pull binary round-trip", async () => {
    const { app } = buildBinaryApp()
    const body = new TextEncoder().encode("fake png data")

    const pushResp = await app.request("/push/images/alice", {
      method: "POST",
      headers: {
        Authorization: "alice",
        "Content-Type": "image/png",
      },
      body,
    })
    expect(pushResp.status).toBe(200)
    const pushBody = (await pushResp.json()) as { hash: string }
    expect(pushBody.hash).toBeTruthy()

    const pullResp = await app.request("/pull/images/alice")
    expect(pullResp.status).toBe(200)
    expect(pullResp.headers.get("content-type")).toBe("image/png")
    expect(pullResp.headers.get("etag")).toBeTruthy()
  })

  it("rejects wrong MIME type", async () => {
    const { app } = buildBinaryApp()
    const resp = await app.request("/push/images/alice", {
      method: "POST",
      headers: {
        Authorization: "alice",
        "Content-Type": "text/plain",
      },
      body: "not an image",
    })
    expect(resp.status).toBe(415)
  })

  it("returns 404 for empty binary pull", async () => {
    const { app } = buildBinaryApp()
    const resp = await app.request("/pull/images/alice")
    expect(resp.status).toBe(404)
  })
})
