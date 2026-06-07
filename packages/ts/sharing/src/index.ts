/**
 * `@drakkar.software/starfish-sharing` — member-cap extension.
 *
 * Public surface: member cap-cert minting with the `readOnly`/`writer`/`admin`
 * scope presets, the per-collection `_members` directory, and the server
 * plugin.
 */

export {
  mintMemberCap,
  mintAudienceCap,
  scopes,
  assertMemberCapShape,
  assertAudienceCapShape,
} from "./cap-mint.js"
export type {
  ScopePreset,
  MintOpts,
  AudienceMintOpts,
  MemberCapShapeCode,
  AudienceCapShapeCode,
} from "./cap-mint.js"

export { createPublicLink, parsePublicLink, redeemPublicLink } from "./public-link.js"
export type {
  CreatePublicLinkOpts,
  PublicLink,
  ParsedPublicLink,
  RedeemPublicLinkOpts,
  RedeemHeaders,
} from "./public-link.js"

export {
  addMemberEntry,
  listMembers,
  removeMemberEntry,
  membersPathFor,
  publishMemberCap,
  fetchMemberCaps,
  fetchMyMemberCap,
  unpublishMemberCap,
} from "./directory.js"
export type {
  DirectoryEntry,
  Directory,
  MemberEntry,
  ListDirectoryOpts,
} from "./directory.js"

export { evictMember } from "./evict.js"
export type {
  EvictMemberParams,
  EvictMemberOpts,
  EvictMemberResult,
  EvictMemberTarget,
} from "./evict.js"

export { makeRegistryRoleEnricher, DEFAULT_SAFE_ID } from "./registry-role-enricher.js"
export type { RegistryRoleEnricherOptions } from "./registry-role-enricher.js"

export { makeIssuerBoundRoleEnricher } from "./issuer-bound-role-enricher.js"
export type { IssuerBoundRoleEnricherOptions } from "./issuer-bound-role-enricher.js"

export { sharingServerPlugin } from "./plugin.js"
