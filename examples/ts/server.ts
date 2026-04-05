/**
 * Basic Starfish server using Hono and filesystem storage (Node.js).
 *
 * Install:
 *   npm install @drakkar.software/starfish-server hono @hono/node-server
 *
 * Run:
 *   npx tsx server.ts
 */

import { serve } from "@hono/node-server"
import { Hono } from "hono"
import type { Context } from "hono"
import {
  createSyncRouter,
  saveConfig,
  type SyncConfig,
  type SyncRouterOptions,
  type AuthResult,
} from "@drakkar.software/starfish-server"
import { FilesystemObjectStore } from "@drakkar.software/starfish-server/node"

const store = new FilesystemObjectStore({ baseDir: "./data" })

const config: SyncConfig = {
  version: 1,
  collections: [
    {
      name: "settings",
      storagePath: "users/{identity}/settings",
      readRoles: ["self"],
      writeRoles: ["self"],
      encryption: "none",
      maxBodyBytes: 65_536,
      allowedMimeTypes: ["application/json"],
    },
    {
      name: "notes",
      storagePath: "users/{identity}/notes",
      readRoles: ["self"],
      writeRoles: ["self"],
      encryption: "identity", // per-user server-side encryption
      maxBodyBytes: 131_072,
      allowedMimeTypes: ["application/json"],
    },
    {
      name: "posts",
      storagePath: "posts/{postId}",
      readRoles: ["public"],
      writeRoles: ["admin"],
      encryption: "none",
      maxBodyBytes: 65_536,
      allowedMimeTypes: ["application/json"],
    },
  ],
}

async function roleResolver(c: Context): Promise<AuthResult> {
  const token = c.req.header("authorization") ?? ""
  // Replace with real auth logic (JWT, API key, etc.)
  if (token.startsWith("Bearer ")) {
    const userId = token.slice("Bearer ".length)
    return { identity: userId, roles: ["user"] }
  }
  return { identity: "anonymous", roles: ["public"] }
}

const syncRouter = createSyncRouter({
  store,
  config,
  roleResolver,
  encryptionSecret: process.env.ENCRYPTION_SECRET ?? "change-me",
})

// Persist config to storage on startup
await saveConfig(store, config)

const app = new Hono()
app.route("/v1", syncRouter)

serve({ fetch: app.fetch, port: 3000 }, (info) => {
  console.log(`Starfish server listening on http://localhost:${info.port}`)
})
