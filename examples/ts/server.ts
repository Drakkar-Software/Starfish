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
  createEntitlementRoleEnricher,
  composeEnrichers,
  createCallbackAuditLogger,
  createGracefulShutdown,
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

  // Per-user entitlement document — admin writes, user reads their own.
  // Contains feature slugs like ["premium-package-1", "paid-cloud-sync"].
  // The entitlementEnricher below translates these into roles at request time.
  {
    name: "entitlements",
    storagePath: "users/{identity}/entitlements",
    readRoles: ["self"],
    writeRoles: ["admin"],
    encryption: "none",
    maxBodyBytes: 4096,
    allowedMimeTypes: ["application/json"],
  },
  // Premium-gated collection — only users with the "premium-package-1" entitlement
  // can read this. Add to or remove from the user's entitlement document to grant/revoke.
  {
    name: "premium-content",
    storagePath: "premium/{contentId}",
    readRoles: ["entitlement:premium-package-1"],
    writeRoles: ["admin"],
    encryption: "none",
    maxBodyBytes: 131_072,
    allowedMimeTypes: ["application/json"],
  },

  // Owner-managed whitelist — only the owner controls who can access the
  // restricted collection below. "self" is auto-granted when {ownerId} in
  // the storagePath matches the authenticated user's identity.
  // No encryption: this is pure RBAC — group encryption is not required.
  {
    name: "whitelist",
    storagePath: "owners/{ownerId}/whitelist",
    readRoles: ["self"],   // only the owner can read their own whitelist
    writeRoles: ["self"],  // only the owner can update their own whitelist
    encryption: "none",
    maxBodyBytes: 65_536,
    allowedMimeTypes: ["application/json"],
  },
  // Restricted data — only users listed in the owner's whitelist can access.
  // The whitelistEnricher below grants "whitelisted" based on that document.
  {
    name: "restricted",
    storagePath: "owners/{ownerId}/restricted",
    readRoles: ["whitelisted"],
    writeRoles: ["whitelisted"],
    encryption: "none",
    maxBodyBytes: 1_048_576,
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

// Grant "group-member" to users listed in groups/{groupId}/members
const groupEnricher = createGroupRoleEnricher({
  store,
  membersPath: "groups/{groupId}/members",
  groupParam: "groupId",
})

// Grant "whitelisted" to users listed in owners/{ownerId}/whitelist
const whitelistEnricher = createGroupRoleEnricher({
  store,
  membersPath: "owners/{ownerId}/whitelist",
  groupParam: "ownerId",
  role: "whitelisted",
})

// Translate per-user entitlement slugs → roles like "entitlement:premium-package-1"
// Reads from users/{identity}/entitlements (default path)
const entitlementEnricher = createEntitlementRoleEnricher({ store })

const syncRouter = createSyncRouter({
  store,
  config,
  roleResolver,
  encryptionSecret: process.env.ENCRYPTION_SECRET ?? "change-me",
  // Compose all enrichers: roles from all are merged into the effective set
  roleEnricher: composeEnrichers(groupEnricher, whitelistEnricher, entitlementEnricher),
  // Audit every pull and push — swap for createCallbackAuditLogger to write to a DB
  audit: createCallbackAuditLogger((entry) => {
    if (!entry.success) {
      console.warn(
        `[AUDIT] ${entry.action.toUpperCase()} ${entry.collection} ` +
        `by ${entry.identity ?? "anonymous"} → ${entry.statusCode}`,
      )
    }
  }),
})

// Persist config to storage on startup
await saveConfig(store, config)

const app = new Hono()
app.route("/v1", syncRouter)

// Graceful shutdown: closes resources on SIGTERM / SIGINT
// Add replicaManager: or queue: here if your server uses them
createGracefulShutdown()

serve({ fetch: app.fetch, port: 3000 }, (info) => {
  console.log(`Starfish server listening on http://localhost:${info.port}`)
})
