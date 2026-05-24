/**
 * Starfish v3.0 server using Hono and filesystem storage (Node.js).
 *
 * v3 changes vs. v2:
 *   • No `encryptionSecret` on `createSyncRouter` — the server holds no keys.
 *   • Auth is cap-cert based: `createCapCertRoleResolver` + a nonce cache +
 *     a revocation store.
 *   • Collections use `encryption: "none"` or `"delegated"` only.
 *
 * Install:
 *   npm install @drakkar.software/starfish-server hono @hono/node-server
 *
 * Run:
 *   npx tsx examples/ts/server.ts
 */

import { serve } from "@hono/node-server"
import { Hono } from "hono"
import {
  createSyncRouter,
  createCapCertRoleResolver,
  createInMemoryNonceCache,
  createInMemoryRevocationStore,
  createGracefulShutdown,
  saveConfig,
  type SyncConfig,
  type NamespaceConfig,
} from "@drakkar.software/starfish-server"
import { createCallbackAuditLogger } from "@drakkar.software/starfish-audit"
import { identitiesServerPlugin } from "@drakkar.software/starfish-identities"
import { sharingServerPlugin } from "@drakkar.software/starfish-sharing"
import { FilesystemObjectStore } from "@drakkar.software/starfish-server/node"

const store = new FilesystemObjectStore({ baseDir: "./data" })

// ---------------------------------------------------------------------------
// Collections — v3 encryption is either "none" or "delegated".
//
//   • "none"      : the server stores plaintext JSON. Use for shareable
//                   metadata, keyring documents, public posts.
//   • "delegated" : the server stores opaque {_encrypted, _epoch} ciphertext.
//                   Clients use createKeyringEncryptor() to read/write.
// ---------------------------------------------------------------------------

const sharedCollections: SyncConfig["collections"] = [
  // Public-read posts.
  {
    name: "posts",
    storagePath: "posts/{postId}",
    readRoles: ["public"],
    writeRoles: ["cap:write:posts"],
    encryption: "none",
    maxBodyBytes: 65_536,
    allowedMimeTypes: ["application/json"],
  },

  // Per-user notes, delegated encryption. The cap-cert resolver enforces
  // that `{identity}` in the URL matches the cap-bound user — so a device
  // of user A cannot read user B's notes even if it forges scope.paths.
  {
    name: "notes",
    storagePath: "users/{identity}/notes",
    readRoles: ["cap:read:notes"],
    writeRoles: ["cap:write:notes"],
    encryption: "delegated",
    maxBodyBytes: 131_072,
    allowedMimeTypes: ["application/json"],
  },

  // The keyring document is plaintext but read-restricted to recipients.
  // Clients pull it, unwrap their entry, and use the recovered CEK to
  // decrypt the encrypted documents in `notes` or `shared-team`.
  {
    name: "notes-keyring",
    storagePath: "users/{identity}/notes/_keyring",
    readRoles: ["cap:read:notes"],
    writeRoles: ["cap:write:notes"],
    encryption: "none",
    maxBodyBytes: 65_536,
    allowedMimeTypes: ["application/json"],
  },

  // Shared-team collection: encrypted under a multi-recipient keyring.
  {
    name: "shared-team",
    storagePath: "shared-team/{docId}",
    readRoles: ["cap:read:shared-team"],
    writeRoles: ["cap:write:shared-team"],
    encryption: "delegated",
    maxBodyBytes: 524_288,
    allowedMimeTypes: ["application/json"],
    listable: true,
  },
  {
    name: "shared-team-keyring",
    storagePath: "shared-team/_keyring",
    readRoles: ["cap:read:shared-team"],
    writeRoles: ["cap:write:shared-team"],
    encryption: "none",
    maxBodyBytes: 65_536,
    allowedMimeTypes: ["application/json"],
  },

  // Per-user entitlement document — admins write, users read their own.
  {
    name: "entitlements",
    storagePath: "users/{identity}/entitlements",
    readRoles: ["cap:read:entitlements"],
    writeRoles: ["cap:write:entitlements"],
    encryption: "none",
    maxBodyBytes: 4096,
    allowedMimeTypes: ["application/json"],
  },

  // ── Plaintext, cap-only shared collection (no keyring) ───────────────────
  // An alternative to the encrypted "shared-team" above for data that does NOT
  // need E2E encryption. Access is authorized purely by signed member caps +
  // expiry (the same mechanism as devices); there is no keyring and no wrapped
  // keys. The owner mints member caps with `mintMemberCap` and either forwards
  // them out-of-band or publishes them into the `_members` list below, from
  // which members fetch their own with `fetchMyMemberCap`.
  {
    name: "shared-board",
    storagePath: "shared-board/{docId}",
    readRoles: ["cap:read:shared-board"],
    writeRoles: ["cap:write:shared-board"],
    encryption: "none",
    maxBodyBytes: 524_288,
    allowedMimeTypes: ["application/json"],
    listable: true,
  },
  // Cap list: ALL members' full signed caps in one document. Read-open so a
  // member fetches their own cap without it being forwarded; owner-only writes.
  // `public` read is safe — a cap is usable only by the holder of its subject
  // private key (the server verifies each request against `cert.sub`), so a
  // readable roster never lets one member act as another. Member caps cannot
  // WRITE here: their scope denies `<col>/_members` (the `member-members-not-denied`
  // barrier), so only the owner's full-scope device cap can publish/evict.
  {
    name: "shared-board-members",
    storagePath: "shared-board/_members",
    readRoles: ["public"],
    writeRoles: ["cap:write:shared-board"],
    encryption: "none",
    maxBodyBytes: 262_144,
    allowedMimeTypes: ["application/json"],
  },
]

// Per-tenant namespaces remain a v3 feature: each tenant gets its own
// storage prefix so the same client/server pair can serve multiple
// isolated user populations.
function makeTenantNamespace(tenantId: string): NamespaceConfig {
  return {
    collections: [
      {
        name: "settings",
        storagePath: `${tenantId}/users/{identity}/settings`,
        readRoles: ["cap:read:settings"],
        writeRoles: ["cap:write:settings"],
        encryption: "none",
        maxBodyBytes: 65_536,
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

// ---------------------------------------------------------------------------
// Cap-cert role resolver.
//
// Replaces the v2 `roleResolver: c => bearer-token-lookup`. The resolver:
//   1. parses `Authorization: Cap <base64>`
//   2. verifies the cap-cert signature, nbf/exp, well-formedness
//   3. verifies `X-Starfish-Sig` over the request body and URL
//   4. consults the nonce cache (replay protection)
//   5. consults the revocation store
//   6. synthesizes roles from the cap-cert's scope (`cap:<op>:<collection>`)
// ---------------------------------------------------------------------------

const nonceCache = createInMemoryNonceCache({
  // Sliding window — the protocol's clock skew is ±5 minutes.
  windowMs: 5 * 60_000,
  maxEntries: 100_000,
})

const revocationStore = createInMemoryRevocationStore()
// In production, persist revocations: rebuild this store from your DB at
// startup and call `revocationStore.revoke(iss, sub, nonce)` whenever an
// admin revokes a device or member cap.

const roleResolver = createCapCertRoleResolver({
  nonceCache,
  revocationStore,
  // When false, requests without an `Authorization: Cap` header are rejected
  // with 401. Leave at default `true` to allow public-read collections.
  allowAnonymous: true,
  // The resolver is secure-by-default: with no plugins it accepts only `device`
  // caps. Wire `identitiesServerPlugin` (device) + `sharingServerPlugin`
  // (member, enforces the member-cap shape barriers incl. the `_keyring` deny)
  // for the kinds this deployment issues.
  plugins: [identitiesServerPlugin, sharingServerPlugin],
})

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

const syncRouter = createSyncRouter({
  store,
  config,
  roleResolver,
  // Optional CORS / security headers — pass `true` for permissive defaults.
  cors: true,
  securityHeaders: true,
  // Audit every pull/push. In production, swap for a DB-writing logger.
  auditLogger: createCallbackAuditLogger((entry) => {
    if (!entry.success) {
      console.warn(
        `[AUDIT] ${entry.action.toUpperCase()} ${entry.collection} ` +
          `by ${entry.identity ?? "anonymous"} -> ${entry.statusCode}`,
      )
    }
  }),
})

// Persist config to storage on startup.
await saveConfig(store, config)

const app = new Hono()
app.route("/v1", syncRouter)

// Graceful shutdown: closes resources on SIGTERM / SIGINT.
createGracefulShutdown()

serve({ fetch: app.fetch, port: 3000 }, (info) => {
  console.log(`Starfish v3 server listening on http://localhost:${info.port}`)
})
