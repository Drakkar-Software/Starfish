import type { ObjectStore } from "../storage/base.js"
import type { RoleEnricher, AuthResult } from "../router/route-builder.js"

export interface EntitlementRoleEnricherOptions {
  /** The ObjectStore to read entitlement documents from. */
  store: ObjectStore
  /**
   * Storage path template for the per-user entitlement document.
   * `{identity}` is replaced with the authenticated user's identity at runtime.
   * Defaults to `"users/{identity}/entitlements"`.
   */
  path?: string
  /**
   * Top-level field in the entitlement document data that holds the list of feature slugs.
   * Defaults to `"features"`.
   */
  field?: string
  /**
   * Prefix applied to each feature slug when constructing the role string.
   * A slug `"premium-package-1"` with prefix `"entitlement"` yields role
   * `"entitlement:premium-package-1"`.
   * Defaults to `"entitlement"`.
   *
   * Change this if your role namespace already uses `"entitlement:"` for something else.
   */
  rolePrefix?: string
  /**
   * How long (in milliseconds) to cache entitlement lookups per user.
   * Set to 0 to disable caching. Defaults to 60 000 (1 minute).
   *
   * Note: each active user adds one cache entry; for very high user counts
   * set this low or disable and use an external cache layer.
   */
  cacheTtlMs?: number
}

interface CacheEntry {
  features: Set<string>
  expiresAt: number
}

/**
 * Creates a `RoleEnricher` that grants roles based on a per-user entitlement document
 * stored in the ObjectStore.
 *
 * The entitlement document must be a standard Starfish JSON document whose `data`
 * field contains a string array under `field` (default `"features"`):
 *
 * ```json
 * { "features": ["premium-package-1", "paid-cloud-sync"] }
 * ```
 *
 * Each slug is translated to a role string: `"${rolePrefix}:${slug}"` (default prefix:
 * `"entitlement"`). Collections gate access using these roles in `readRoles`/`writeRoles`:
 *
 * ```ts
 * { readRoles: ["entitlement:premium-package-1"], writeRoles: ["admin"] }
 * ```
 *
 * Recommended entitlement collection config:
 * ```ts
 * { name: "entitlements", storagePath: "users/{identity}/entitlements",
 *   readRoles: ["self"], writeRoles: ["admin"],
 *   encryption: "none", maxBodyBytes: 4096, allowedMimeTypes: ["application/json"] }
 * ```
 *
 * Usage:
 * ```ts
 * const entitlementEnricher = createEntitlementRoleEnricher({ store })
 *
 * const router = createSyncRouter({
 *   store, config, roleResolver,
 *   roleEnricher: entitlementEnricher,
 * })
 * ```
 *
 * When combined with a group enricher, use `composeEnrichers`:
 * ```ts
 * import { composeEnrichers } from "@drakkar.software/starfish-server"
 * roleEnricher: composeEnrichers(groupEnricher, entitlementEnricher)
 * ```
 *
 * Note: the enricher fires for every collection request, including the entitlement
 * collection itself. For that collection `readRoles: ["self"]` already passes before
 * enrichment — the extra entitlement roles are ignored for that request.
 */
export function createEntitlementRoleEnricher(opts: EntitlementRoleEnricherOptions): RoleEnricher {
  const {
    store,
    path = "users/{identity}/entitlements",
    field = "features",
    rolePrefix = "entitlement",
    cacheTtlMs = 60_000,
  } = opts

  const cache = new Map<string, CacheEntry>()

  async function resolveFeatures(identity: string): Promise<Set<string>> {
    const now = Date.now()

    if (cacheTtlMs > 0) {
      const cached = cache.get(identity)
      if (cached && cached.expiresAt > now) {
        return cached.features
      }
    }

    const key = path.replace("{identity}", identity)
    const raw = await store.getString(key)

    let features = new Set<string>()
    if (raw != null) {
      try {
        // StoredDocument format: { v: 1, data: { features: [...] }, timestamps: {...}, hash: "..." }
        const doc = JSON.parse(raw) as { data?: Record<string, unknown> }
        const list = doc.data?.[field]
        if (Array.isArray(list)) {
          features = new Set(list.filter((s): s is string => typeof s === "string"))
        }
      } catch {
        // Corrupt document — treat as no entitlements
      }
    }

    if (cacheTtlMs > 0) {
      cache.set(identity, { features, expiresAt: now + cacheTtlMs })
    }

    return features
  }

  return async function entitlementRoleEnricher(
    auth: AuthResult,
    _params: Record<string, string>,
  ): Promise<string[]> {
    const features = await resolveFeatures(auth.identity)
    return Array.from(features, (slug) => `${rolePrefix}:${slug}`)
  }
}
