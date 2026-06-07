import type { RoleEnricher, AuthResult } from "./role-enricher-types.js"

export interface IssuerBoundRoleEnricherOptions {
  /** The path param holding the owner id (e.g. `"ownerId"`). */
  ownerParam: string
  /** Role granted to the owner's own device cap. */
  ownerRole: string
  /**
   * Role granted to the owner and to caps delegated by the owner for one of
   * `collections`.
   */
  readerRole: string
  /**
   * Role granted (in addition to `readerRole`) to a delegated cap carrying
   * `cap:write:<col>` for one of `collections`, UNLESS the request targets the
   * guard doc.
   */
  writerRole: string
  /**
   * Collections whose `delegated:` / `cap:write:` roles admit the share
   * (e.g. `["pubspace", "pubstream"]`).
   */
  collections: string[]
  /**
   * The path param checked against `guardValue` to withhold `writerRole`
   * (e.g. `"docId"`).
   */
  guardParam: string
  /**
   * The value of `guardParam` that withholds `writerRole` (e.g. `"_rooms"`).
   */
  guardValue: string
}

/**
 * Creates a `RoleEnricher` that grants issuer-bound public-share roles decided
 * PURELY from the requester's cap (no store access), generalizing the
 * "public share keyed by a free `{ownerId}`" pattern.
 *
 * A path like `pubspaces/{ownerId}/{spaceId}/{docId}` would let any signed cap
 * read any owner's public resource under a plain `cap:read:<col>` role. Gate on
 * synthesized roles instead:
 *
 * - `ownerRole`  — owner managing their own public resource. Uses a DEVICE cap,
 *                  so `auth.identity === ownerId`. Gates WRITES.
 * - `readerRole` — a MEMBER/AUDIENCE cap the owner minted; the resolver emits
 *                  `delegated:<issUserId>:<col>`, so read is granted only when
 *                  the issuer is the path's owner. Gates READS.
 * - `writerRole` — an owner-minted member cap that also carries write authority
 *                  (`cap:write:<col>`). Gates WRITES on non-registry docs.
 *
 * Two subtleties (both were latent bugs in simpler share forms):
 *
 * - DEVICE caps never get a `delegated:` role (the resolver emits it for
 *   member/audience caps only). So the owner is granted `readerRole` ALONGSIDE
 *   `ownerRole` — otherwise the owner could write but not READ their own data.
 * - A read/write link must NOT let a guest rewrite the registry doc, so
 *   `writerRole` is withheld when `params[guardParam] === guardValue`.
 *
 * Usage:
 * ```ts
 * const enricher = makeIssuerBoundRoleEnricher({
 *   ownerParam: "ownerId",
 *   ownerRole: "pubspace:owner",
 *   readerRole: "pubspace:reader",
 *   writerRole: "pubspace:writer",
 *   collections: ["pubspace", "pubstream"],
 *   guardParam: "docId",
 *   guardValue: "_rooms",
 * })
 * ```
 */
export function makeIssuerBoundRoleEnricher(
  opts: IssuerBoundRoleEnricherOptions,
): RoleEnricher {
  const { ownerParam, ownerRole, readerRole, writerRole, collections, guardParam, guardValue } =
    opts

  return async function issuerBoundRoleEnricher(
    auth: AuthResult,
    params: Record<string, string>,
  ): Promise<string[]> {
    const ownerId = params[ownerParam]
    if (!ownerId || !auth.identity) return []
    const roles: string[] = []
    // Owner's own device cap (auth.identity === ownerId): full access. Grant
    // reader too — a device cap has no `delegated:` role, so without this the
    // owner couldn't read their own public resource.
    if (auth.identity === ownerId) {
      roles.push(ownerRole)
      roles.push(readerRole)
    }
    // A member/audience cap issued BY this owner → may read (and write
    // non-registry docs if it carries write). The resolver emits
    // `delegated:<iss>:<col>` for member/audience caps.
    const delegatedByOwner = collections.some((col) =>
      auth.roles.includes(`delegated:${ownerId}:${col}`),
    )
    if (delegatedByOwner) {
      roles.push(readerRole)
      const canWrite = collections.some((col) => auth.roles.includes(`cap:write:${col}`))
      if (params[guardParam] !== guardValue && canWrite) {
        roles.push(writerRole)
      }
    }
    return roles
  }
}
