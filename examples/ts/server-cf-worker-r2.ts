/**
 * Starfish server on Cloudflare Workers with native R2 binding.
 *
 * Uses the R2 bucket binding directly — no S3 SDK, no extra credentials.
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
 *   [vars]
 *   ENCRYPTION_SECRET = "change-me"
 *
 * Deploy:
 *   npx wrangler deploy
 */

import { Hono } from "hono"
import type { Context } from "hono"
import {
  createSyncRouter,
  saveConfig,
  type ObjectStore,
  type SyncConfig,
  type AuthResult,
} from "@drakkar.software/starfish-server"

// ---------------------------------------------------------------------------
// R2 ObjectStore using native Worker binding
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
// Cloudflare Worker env bindings
// ---------------------------------------------------------------------------

type Env = {
  BUCKET: R2Bucket
  ENCRYPTION_SECRET: string
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

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
      encryption: "identity",
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

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

async function roleResolver(c: Context): Promise<AuthResult> {
  const token = c.req.header("authorization") ?? ""
  // Replace with real auth (JWT, API key, etc.)
  if (token.startsWith("Bearer ")) {
    const userId = token.slice("Bearer ".length)
    return { identity: userId, roles: ["user"] }
  }
  return { identity: "anonymous", roles: ["public"] }
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

const app = new Hono<{ Bindings: Env }>()

let cachedRouter: Hono | null = null

function getSyncRouter(env: Env): Hono {
  if (cachedRouter) return cachedRouter

  const store = new R2ObjectStore(env.BUCKET)

  cachedRouter = createSyncRouter({
    store,
    config,
    roleResolver,
    encryptionSecret: env.ENCRYPTION_SECRET,
  })

  // Persist config to storage (fire-and-forget; idempotent)
  saveConfig(store, config).catch(() => {})

  return cachedRouter
}

app.route("/v1", new Hono().all("/*", (c) => getSyncRouter(c.env).fetch(c.req.raw)))

export default app
