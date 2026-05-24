/**
 * Starfish v3.0 server on Cloudflare Workers with native R2 binding.
 *
 * Uses the R2 bucket binding directly — no S3 SDK, no extra credentials.
 *
 * v3 changes vs. v2:
 *   • No `encryptionSecret` on `createSyncRouter`. The server holds no keys.
 *   • Auth is cap-cert based via `createCapCertRoleResolver`.
 *
 * Install:
 *   npm install @drakkar.software/starfish-server hono
 *
 * wrangler.toml:
 *   name = "starfish-server"
 *   main = "server-cf-worker-r2.ts"
 *   compatibility_date = "2024-12-01"
 *
 *   [[r2_buckets]]
 *   binding = "BUCKET"
 *   bucket_name = "starfish"
 *
 * Deploy:
 *   npx wrangler deploy
 */

import { Hono } from "hono"
import {
  createSyncRouter,
  createCapCertRoleResolver,
  createInMemoryNonceCache,
  createInMemoryRevocationStore,
  saveConfig,
  type ObjectStore,
  type SyncConfig,
} from "@drakkar.software/starfish-server"

// ---------------------------------------------------------------------------
// R2 ObjectStore — native Worker binding.
// ---------------------------------------------------------------------------

class R2ObjectStore implements ObjectStore {
  constructor(private bucket: R2Bucket) {}

  async getString(key: string): Promise<string | null> {
    const obj = await this.bucket.get(key)
    if (!obj) return null
    return obj.text()
  }

  async put(
    key: string,
    body: string,
    opts?: { contentType?: string; cacheControl?: string },
  ): Promise<void> {
    await this.bucket.put(key, body, {
      httpMetadata: {
        contentType: opts?.contentType,
        cacheControl: opts?.cacheControl,
      },
    })
  }

  async getBytes(
    key: string,
  ): Promise<{ body: Uint8Array; contentType: string } | null> {
    const obj = await this.bucket.get(key)
    if (!obj) return null
    return {
      body: new Uint8Array(await obj.arrayBuffer()),
      contentType: obj.httpMetadata?.contentType ?? "application/octet-stream",
    }
  }

  async putBytes(
    key: string,
    body: Uint8Array,
    opts: { contentType: string; cacheControl?: string },
  ): Promise<void> {
    await this.bucket.put(key, body, {
      httpMetadata: {
        contentType: opts.contentType,
        cacheControl: opts.cacheControl,
      },
    })
  }

  async listKeys(
    prefix: string,
    opts?: { startAfter?: string; limit?: number },
  ): Promise<string[]> {
    const listed = await this.bucket.list({
      prefix,
      startAfter: opts?.startAfter,
      limit: opts?.limit,
    })
    return listed.objects.map((o) => o.key)
  }

  async delete(key: string): Promise<void> {
    await this.bucket.delete(key)
  }

  async deleteMany(keys: string[]): Promise<void> {
    if (keys.length === 0) return
    await this.bucket.delete(keys)
  }
}

// ---------------------------------------------------------------------------
// Worker env bindings.
// ---------------------------------------------------------------------------

type Env = {
  BUCKET: R2Bucket
}

// ---------------------------------------------------------------------------
// Config — v3 encryption: "none" or "delegated".
// ---------------------------------------------------------------------------

const config: SyncConfig = {
  version: 1,
  collections: [
    {
      name: "posts",
      storagePath: "posts/{postId}",
      readRoles: ["public"],
      writeRoles: ["cap:write:posts"],
      encryption: "none",
      maxBodyBytes: 65_536,
      allowedMimeTypes: ["application/json"],
    },
    {
      name: "settings",
      storagePath: "users/{identity}/settings",
      readRoles: ["cap:read:settings"],
      writeRoles: ["cap:write:settings"],
      encryption: "none",
      maxBodyBytes: 65_536,
      allowedMimeTypes: ["application/json"],
    },
    {
      name: "notes",
      storagePath: "users/{identity}/notes",
      readRoles: ["cap:read:notes"],
      writeRoles: ["cap:write:notes"],
      encryption: "delegated",
      maxBodyBytes: 131_072,
      allowedMimeTypes: ["application/json"],
    },
    {
      name: "notes-keyring",
      storagePath: "users/{identity}/notes/_keyring",
      readRoles: ["cap:read:notes"],
      writeRoles: ["cap:write:notes"],
      encryption: "none",
      maxBodyBytes: 65_536,
      allowedMimeTypes: ["application/json"],
    },
  ],
}

// ---------------------------------------------------------------------------
// App — build a fresh router per request to bind the R2 store to env.
// ---------------------------------------------------------------------------

const app = new Hono<{ Bindings: Env }>()

let cachedRouter: Hono | null = null

function getSyncRouter(env: Env): Hono {
  if (cachedRouter) return cachedRouter

  const store = new R2ObjectStore(env.BUCKET)

  // Nonce cache + revocation store are per-Worker-instance. For multi-region
  // deployments, replace with Durable Object / KV-backed implementations.
  const nonceCache = createInMemoryNonceCache({
    windowMs: 5 * 60_000,
    maxEntries: 100_000,
  })
  const revocationStore = createInMemoryRevocationStore()

  // Secure by default: with no `plugins` the resolver accepts only `device`
  // caps. This Worker example is device + anonymous-read only; to accept
  // `member` caps (sharing) add `plugins: [identitiesServerPlugin,
  // sharingServerPlugin]` (from starfish-identities / starfish-sharing).
  const roleResolver = createCapCertRoleResolver({
    nonceCache,
    revocationStore,
    allowAnonymous: true,
  })

  cachedRouter = createSyncRouter({
    store,
    config,
    roleResolver,
    cors: true,
    securityHeaders: true,
  })

  // Persist config to storage (fire-and-forget; idempotent).
  saveConfig(store, config).catch(() => {})

  return cachedRouter
}

app.route("/v1", new Hono().all("/*", (c) => getSyncRouter(c.env).fetch(c.req.raw)))

export default app
