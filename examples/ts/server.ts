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
  createGroupRoleEnricher,
  saveConfig,
  type SyncConfig,
  type SyncRouterOptions,
  type AuthResult,
  type NamespaceConfig,
} from "@drakkar.software/starfish-server"
import { FilesystemObjectStore } from "@drakkar.software/starfish-server/node"

const store = new FilesystemObjectStore({ baseDir: "./data" })

// Shared collections at /pull/... and /push/...
const sharedCollections: SyncConfig["collections"] = [
  {
    name: "posts",
    storagePath: "posts/{postId}",
    readRoles: ["public"],
    writeRoles: ["admin"],
    encryption: "none",
    maxBodyBytes: 65_536,
    allowedMimeTypes: ["application/json"],
  },

  // Group keyring — plaintext, admin-write, member-read.
  // Contains per-member ECDH-wrapped copies of the Group Encryption Key.
  {
    name: "keyring",
    storagePath: "groups/{groupId}/keyring",
    readRoles: ["group-member"],
    writeRoles: ["group-admin"],
    encryption: "none",
    maxBodyBytes: 65_536,
    allowedMimeTypes: ["application/json"],
  },

  // Encrypted group chat — one document per group per day.
  // encryption: "group" means the server stores opaque ciphertext;
  // clients use createGroupEncryptor() to encrypt/decrypt.
  {
    name: "chat",
    storagePath: "groups/{groupId}/chat/{day}",
    readRoles: ["group-member"],
    writeRoles: ["group-member"],
    encryption: "group",
    maxBodyBytes: 524_288,
    allowedMimeTypes: ["application/json"],
    listable: true,
  },

  // Group membership roster — read/written by group admins.
  // The roleEnricher below reads this to grant "group-member".
  {
    name: "group-members",
    storagePath: "groups/{groupId}/members",
    readRoles: ["group-admin"],
    writeRoles: ["group-admin"],
    encryption: "none",
    maxBodyBytes: 65_536,
    allowedMimeTypes: ["application/json"],
  },
]

// Per-tenant namespaces: /{tenant}/pull/... and /{tenant}/push/...
// Each tenant has its own storagePath prefix for storage isolation.
function makeTenantNamespace(tenantId: string): NamespaceConfig {
  return {
    collections: [
      {
        name: "settings",
        storagePath: `${tenantId}/users/{identity}/settings`,
        readRoles: ["self"],
        writeRoles: ["self"],
        encryption: "none",
        maxBodyBytes: 65_536,
        allowedMimeTypes: ["application/json"],
      },
      {
        name: "notes",
        storagePath: `${tenantId}/users/{identity}/notes`,
        readRoles: ["self"],
        writeRoles: ["self"],
        encryption: "identity", // per-user server-side encryption
        maxBodyBytes: 131_072,
        allowedMimeTypes: ["application/json"],
      },
    ],
  }
}

const config: SyncConfig = {
  version: 1,
  collections: sharedCollections,
  namespaces: {
    acme: makeTenantNamespace("acme"),
    globex: makeTenantNamespace("globex"),
  },
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
  // Grant "group-member" to users whose identity appears in groups/{groupId}/members
  roleEnricher: createGroupRoleEnricher({
    store,
    membersPath: "groups/{groupId}/members",
    groupParam: "groupId",
  }),
})

// Persist config to storage on startup
await saveConfig(store, config)

const app = new Hono()
app.route("/v1", syncRouter)

serve({ fetch: app.fetch, port: 3000 }, (info) => {
  console.log(`Starfish server listening on http://localhost:${info.port}`)
})
