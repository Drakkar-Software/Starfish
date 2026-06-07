import type { ObjectStore, RoleEnricher, AuthResult } from "./role-enricher-types.js"

/**
 * Default id charset — tighter than starfish's SAFE_PARAM. Disallows `.`, `:`,
 * `@` so ids cannot collide after downstream sanitization (e.g. a NATS-subject
 * sanitizer mapping `[^a-zA-Z0-9\-_~%] → '-'`). Anchored for use with a full
 * match (see `makeRegistryRoleEnricher`).
 */
export const DEFAULT_SAFE_ID = /^[a-zA-Z0-9_-]+$/

export interface RegistryRoleEnricherOptions {
  /** The path param holding the resource id (e.g. `"productId"`). */
  idParam: string
  /**
   * Storage path template with a `{id}` placeholder for the resource id
   * (e.g. `"products/{id}/_registry"`).
   */
  registryPath: string
  /** Role granted to the owner (e.g. `"product:owner"`). */
  ownerRole: string
  /** Role granted to owner + members (e.g. `"product:member"`). */
  memberRole: string
  /**
   * When `true` (default), a missing registry doc grants `[ownerRole, memberRole]`
   * (trust-on-first-use). When `false`, a missing doc grants `[]` (strict;
   * used by SSE/events paths).
   */
  allowTofu?: boolean
  /**
   * Regex the id must fully match (anchored). Defaults to {@link DEFAULT_SAFE_ID}.
   */
  idPattern?: RegExp
}

function accessFromRegistry(raw: string): { owner: string | null; members: string[] } {
  let doc: unknown
  try {
    doc = JSON.parse(raw)
  } catch {
    return { owner: null, members: [] }
  }
  // Tolerate both the stored sync-document shape (`{ data: {...} }`) and a bare object.
  const data =
    doc && typeof doc === "object" && "data" in (doc as Record<string, unknown>)
      ? (doc as Record<string, unknown>).data
      : doc
  if (!data || typeof data !== "object") {
    return { owner: null, members: [] }
  }
  const rec = data as Record<string, unknown>
  const owner = typeof rec.owner === "string" ? rec.owner : null
  const members = Array.isArray(rec.members)
    ? rec.members.filter((m): m is string => typeof m === "string")
    : []
  return { owner, members }
}

/**
 * Creates a `RoleEnricher` that grants `ownerRole` / `memberRole` from an
 * authoritative owner-written registry document, generalizing the
 * "registry doc doubles as the access record" pattern.
 *
 * A collection keyed by a free `{id}` whose `_registry` document stores
 * `{ owner, members: [...userIds] }`. A plain cap role would let any
 * authenticated identity read/overwrite any id, so we gate on two synthesized
 * roles decided from that owner-written record:
 *
 * - `ownerRole`  — the creator. With `allowTofu: true` (default) the FIRST writer
 *                  to an id is granted ownership (trust-on-first-use).
 * - `memberRole` — owner OR any userId listed in `members`.
 *
 * Security properties (preserved exactly from the originating app enrichers):
 *
 * - Fails CLOSED on any store error: if `store.getString` REJECTS, the error
 *   propagates (the resolver turns it into a 500). Letting transient outages
 *   fall through to "no registry yet ⇒ open TOFU" would let an attacker who can
 *   induce store errors take over established resources.
 * - The id must FULLY match `idPattern` (default {@link DEFAULT_SAFE_ID}),
 *   guarding against trailing-newline / partial-match bypasses.
 * - An owner-less / unparseable stored doc fails CLOSED (`[]`) rather than
 *   re-opening TOFU.
 *
 * The `allowTofu: false` strict variant (used by SSE/events paths) requires a
 * recorded role in an existing registry doc.
 *
 * Usage:
 * ```ts
 * const enricher = makeRegistryRoleEnricher(store, {
 *   idParam: "productId",
 *   registryPath: "products/{id}/_registry",
 *   ownerRole: "product:owner",
 *   memberRole: "product:member",
 * })
 * ```
 */
export function makeRegistryRoleEnricher(
  store: ObjectStore,
  opts: RegistryRoleEnricherOptions,
): RoleEnricher {
  const {
    idParam,
    registryPath,
    ownerRole,
    memberRole,
    allowTofu = true,
    idPattern = DEFAULT_SAFE_ID,
  } = opts

  return async function registryRoleEnricher(
    auth: AuthResult,
    params: Record<string, string>,
  ): Promise<string[]> {
    const resourceId = params[idParam]
    if (!resourceId || !auth.identity) return []
    // Full match — guard against trailing-newline / partial-match bypass.
    const m = idPattern.exec(resourceId)
    if (m === null || m[0] !== resourceId) return []
    // store.getString is contracted to return null for missing keys; any reject
    // here means a real store error and we fail closed (the resolver returns
    // 500 → client retries; better than silently granting TOFU during an
    // outage). Do NOT swallow.
    const raw = await store.getString(registryPath.replace("{id}", resourceId))
    if (raw == null) {
      return allowTofu ? [ownerRole, memberRole] : []
    }
    const { owner, members } = accessFromRegistry(raw)
    if (owner === null) {
      // Owner-less / unparseable stored doc → fail closed. Re-opening TOFU here
      // would invite takeover by the next writer.
      console.warn(`registry ${resourceId} has no owner field; denying.`)
      return []
    }
    if (owner === auth.identity) return [ownerRole, memberRole]
    if (members.includes(auth.identity)) return [memberRole]
    return []
  }
}
