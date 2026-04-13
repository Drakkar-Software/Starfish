import type { ObjectStore } from "../storage/base.js"
import type { RoleEnricher, AuthResult } from "../router/route-builder.js"

export interface GroupRoleEnricherOptions {
  /** The ObjectStore to read membership documents from. */
  store: ObjectStore
  /**
   * storagePath template for the members document.
   * Must contain a placeholder matching `groupParam`.
   * Example: `"groups/{groupId}/members"`
   */
  membersPath: string
  /**
   * Name of the URL path parameter that identifies the group.
   * Must appear in `membersPath` and in the protected collection's storagePath.
   * Example: `"groupId"`
   */
  groupParam: string
  /**
   * Top-level field in the members document data that holds the list of member identities.
   * Defaults to `"members"`.
   */
  membersField?: string
  /**
   * Role string granted to members.
   * Defaults to `"group-member"`.
   */
  role?: string
  /**
   * How long (in milliseconds) to cache membership lookups.
   * Set to 0 to disable caching. Defaults to 60 000 (1 minute).
   */
  cacheTtlMs?: number
}

interface CacheEntry {
  members: Set<string>
  expiresAt: number
}

/**
 * Creates a `RoleEnricher` that grants a role to users who appear in a
 * group membership document stored in the given ObjectStore.
 *
 * The members document must be a standard Starfish JSON document whose
 * `data` field contains a string array under `membersField` (default `"members"`):
 *
 * ```json
 * { "members": ["alice", "bob", "charlie"] }
 * ```
 *
 * Usage:
 * ```ts
 * const enricher = createGroupRoleEnricher({
 *   store,
 *   membersPath: "groups/{groupId}/members",
 *   groupParam: "groupId",
 * })
 *
 * const router = createSyncRouter({ store, config, roleResolver, roleEnricher: enricher })
 * ```
 */
export function createGroupRoleEnricher(opts: GroupRoleEnricherOptions): RoleEnricher {
  const {
    store,
    membersPath,
    groupParam,
    membersField = "members",
    role = "group-member",
    cacheTtlMs = 60_000,
  } = opts

  const cache = new Map<string, CacheEntry>()

  async function resolveMembers(groupId: string): Promise<Set<string>> {
    const now = Date.now()

    if (cacheTtlMs > 0) {
      const cached = cache.get(groupId)
      if (cached && cached.expiresAt > now) {
        return cached.members
      }
    }

    const key = membersPath.replace(`{${groupParam}}`, groupId)
    const raw = await store.getString(key)

    let members = new Set<string>()
    if (raw != null) {
      try {
        // StoredDocument format: { v: 1, data: { members: [...] }, timestamps: {...}, hash: "..." }
        const doc = JSON.parse(raw) as { data?: Record<string, unknown> }
        const list = doc.data?.[membersField]
        if (Array.isArray(list)) {
          members = new Set(list.filter((m): m is string => typeof m === "string"))
        }
      } catch {
        // Corrupt document — treat as empty membership
      }
    }

    if (cacheTtlMs > 0) {
      cache.set(groupId, { members, expiresAt: now + cacheTtlMs })
    }

    return members
  }

  return async function groupRoleEnricher(
    auth: AuthResult,
    params: Record<string, string>,
  ): Promise<string[]> {
    const groupId = params[groupParam]
    if (!groupId) return []

    const members = await resolveMembers(groupId)
    return members.has(auth.identity) ? [role] : []
  }
}
