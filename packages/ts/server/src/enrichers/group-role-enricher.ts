import type { ObjectStore } from "../storage/base.js"
import type { RoleEnricher, AuthResult } from "../router/route-builder.js"

interface GroupRoleEnricherBaseOptions {
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
   * Must be >= 0. Set to 0 to disable caching. Defaults to 60 000 (1 minute).
   */
  cacheTtlMs?: number
}

/**
 * Candidacy options — only available when `candidacyPath` is provided.
 * Setting `candidacyPath` is a global prerequisite; candidacy must also be
 * enabled per-group via `candidacyEnabledField` in each group's members document.
 */
interface GroupRoleEnricherCandidacyOnOptions {
  /**
   * storagePath template for individual candidacy documents.
   * Must contain a placeholder matching `groupParam` and `{identity}` (the applicant's identity).
   * Example: `"groups/{groupId}/candidacies/{identity}"`
   */
  candidacyPath: string
  /**
   * Role string granted to users with a pending candidacy.
   * Defaults to `"group-candidate"`.
   */
  candidacyRole?: string
  /**
   * Field name in the candidacy document data that holds the application status.
   * Expected values: `"pending"` | `"accepted"` | `"denied"`.
   * Defaults to `"status"`.
   */
  candidacyStatusField?: string
  /**
   * Field name in the members document data that enables candidacy for a specific group.
   * When absent or falsy, candidacy is disabled for that group regardless of the global setting.
   * Defaults to `"candidacyEnabled"`.
   */
  candidacyEnabledField?: string
  /**
   * How long (in milliseconds) to cache candidacy document lookups.
   * Must be >= 0. Set to 0 to disable caching. Defaults to the value of `cacheTtlMs`.
   */
  candidacyCacheTtlMs?: number
}

/** When `candidacyPath` is absent, all other candidacy fields must also be absent. */
interface GroupRoleEnricherCandidacyOffOptions {
  candidacyPath?: undefined
  candidacyRole?: undefined
  candidacyStatusField?: undefined
  candidacyEnabledField?: undefined
  candidacyCacheTtlMs?: undefined
}

/**
 * Options for `createGroupRoleEnricher`.
 *
 * Candidacy support is enabled by providing `candidacyPath`. When absent, all
 * `candidacy*` fields are unavailable at the type level, preventing accidental
 * misconfiguration.
 */
export type GroupRoleEnricherOptions = GroupRoleEnricherBaseOptions &
  (GroupRoleEnricherCandidacyOffOptions | GroupRoleEnricherCandidacyOnOptions)

type CandidacyStatus = "pending" | "accepted" | "denied"

interface MembersCacheEntry {
  members: Set<string>
  candidacyEnabled: boolean
  expiresAt: number
}

interface CandidacyCacheEntry {
  status: CandidacyStatus | null
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
 * ### Group candidacy
 *
 * When `candidacyPath` is set, users can apply to join a group by pushing a
 * candidacy document with `{ status: "pending", message: "reason" }`. Pending
 * applicants receive `candidacyRole` (default `"group-candidate"`) until an admin
 * accepts or denies the application. Candidacy must also be enabled per-group by
 * setting `candidacyEnabled: true` in the members document.
 *
 * Usage:
 * ```ts
 * const enricher = createGroupRoleEnricher({
 *   store,
 *   membersPath: "groups/{groupId}/members",
 *   groupParam: "groupId",
 *   candidacyPath: "groups/{groupId}/candidacies/{identity}",
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
    candidacyPath,
    candidacyRole = "group-candidate",
    candidacyStatusField = "status",
    candidacyEnabledField = "candidacyEnabled",
  } = opts

  // Construction-time validation
  if (cacheTtlMs < 0) throw new Error("cacheTtlMs must be >= 0")
  if (opts.candidacyCacheTtlMs !== undefined && opts.candidacyCacheTtlMs < 0) {
    throw new Error("candidacyCacheTtlMs must be >= 0")
  }
  if (!membersPath.includes(`{${groupParam}}`)) {
    throw new Error(
      `membersPath "${membersPath}" must contain the {${groupParam}} placeholder`,
    )
  }
  if (candidacyPath !== undefined) {
    if (!candidacyPath) {
      throw new Error("candidacyPath must not be empty")
    }
    if (!candidacyPath.includes("{identity}")) {
      throw new Error(`candidacyPath "${candidacyPath}" must contain the {identity} placeholder`)
    }
    if (!candidacyPath.includes(`{${groupParam}}`)) {
      throw new Error(
        `candidacyPath "${candidacyPath}" must contain the {${groupParam}} placeholder`,
      )
    }
  }

  const candidacyCacheTtlMs = opts.candidacyCacheTtlMs ?? cacheTtlMs

  const membersCache = new Map<string, MembersCacheEntry>()
  // candidacyCache key: "${groupId}\0${identity}" — null byte separator avoids collisions
  // when groupId or identity values contain colons or other separator characters.
  const candidacyCache = new Map<string, CandidacyCacheEntry>()

  async function resolveMembersDoc(
    groupId: string,
  ): Promise<{ members: Set<string>; candidacyEnabled: boolean }> {
    const now = Date.now()

    if (cacheTtlMs > 0) {
      const cached = membersCache.get(groupId)
      if (cached && cached.expiresAt > now) {
        return { members: cached.members, candidacyEnabled: cached.candidacyEnabled }
      }
    }

    const key = membersPath.replace(`{${groupParam}}`, groupId)
    const raw = await store.getString(key)

    if (raw == null) {
      return { members: new Set(), candidacyEnabled: false }
    }

    try {
      // StoredDocument format: { v: 1, data: { members: [...] }, timestamps: {...}, hash: "..." }
      const doc = JSON.parse(raw) as { data?: Record<string, unknown> }
      const data = doc.data ?? {}
      const list = data[membersField]
      const members = Array.isArray(list)
        ? new Set(list.filter((m): m is string => typeof m === "string"))
        : new Set<string>()
      const candidacyEnabled = Boolean(data[candidacyEnabledField])

      if (cacheTtlMs > 0) {
        membersCache.set(groupId, { members, candidacyEnabled, expiresAt: now + cacheTtlMs })
      }
      return { members, candidacyEnabled }
    } catch (err) {
      if (!(err instanceof SyntaxError)) throw err
      console.error("group-enricher: corrupt membership document at %s:", key, err)
      // Do not cache corrupt result — return empty without writing to cache
      return { members: new Set(), candidacyEnabled: false }
    }
  }

  async function resolveCandidacyStatus(
    groupId: string,
    identity: string,
  ): Promise<CandidacyStatus | null> {
    // Null byte separator prevents cache key collisions when groupId or identity contain colons
    const cacheKey = `${groupId}\0${identity}`
    const now = Date.now()

    if (candidacyCacheTtlMs > 0) {
      const cached = candidacyCache.get(cacheKey)
      if (cached && cached.expiresAt > now) {
        return cached.status
      }
    }

    // Only substitute the group param and {identity} — never loop over all URL params,
    // as a URL param named "identity" would shadow the auth identity substitution.
    const key = candidacyPath!
      .replace(`{${groupParam}}`, groupId)
      .replace("{identity}", identity)

    const raw = await store.getString(key)

    if (raw == null) {
      return null
    }

    try {
      // StoredDocument format: { v: 1, data: { status: "..." }, timestamps: {...}, hash: "..." }
      const doc = JSON.parse(raw) as { data?: Record<string, unknown> }
      const s = doc.data?.[candidacyStatusField]
      const status: CandidacyStatus | null =
        s === "pending" || s === "accepted" || s === "denied" ? s : null

      if (candidacyCacheTtlMs > 0) {
        candidacyCache.set(cacheKey, { status, expiresAt: now + candidacyCacheTtlMs })
      }
      return status
    } catch (err) {
      if (!(err instanceof SyntaxError)) throw err
      console.error("group-enricher: corrupt candidacy document at %s:", key, err)
      // Do not cache corrupt result — return null without writing to cache
      return null
    }
  }

  return async function groupRoleEnricher(
    auth: AuthResult,
    params: Record<string, string>,
  ): Promise<string[]> {
    const groupId = params[groupParam]
    if (!groupId) return []

    const { members, candidacyEnabled } = await resolveMembersDoc(groupId)

    if (members.has(auth.identity)) return [role]

    if (!candidacyPath) return []
    if (!candidacyEnabled) return []

    const status = await resolveCandidacyStatus(groupId, auth.identity)
    return status === "pending" ? [candidacyRole] : []
  }
}
