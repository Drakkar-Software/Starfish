/**
 * `@drakkar.software/starfish-spaces` — public API entry point.
 *
 * Re-exports every public symbol from the domain modules. Import from this
 * package rather than from individual module files.
 */

// ── Config & layout ───────────────────────────────────────────────────────────
export type {
  SpaceLayout,
  SpacesConfig,
  KvAdapter,
  ID,
  CapMap,
  PubAccessMap,
  MuteValue,
  MutePrefs,
  ReadPrefs,
  Space,
  ObjectType,
  ObjectContentKind,
  NodeAccess,
  ObjectNode,
  ObjectsIndex,
  SealedBlob,
} from "./config.js"
export { configureSpaces, getSpacesConfig } from "./config.js"

// ── Default layout ─────────────────────────────────────────────────────────────
export { defaultSpaceLayout, defaultUserIdFromEdPub, OBJECT_COLLECTIONS, USER_ID_HEX_LENGTH, RECIPIENT_LABEL_LEN } from "./layout.js"

// ── Session ────────────────────────────────────────────────────────────────────
export type { Session, BuildSessionOpts, BuildLinkedSessionOpts, LinkedIdentity } from "./session.js"
export {
  buildSession,
  buildLinkedSession,
  deriveSession,
  fingerprintFromUserId,
  generateSeedWords,
  isValidSeed,
  ownerTrustedAdders,
} from "./session.js"

// ── Client helpers ─────────────────────────────────────────────────────────────
export type { DeviceKeys, ClientOpts, PublicProfile } from "./client.js"
export {
  makeSpaceClient,
  makeAnonSpaceClient,
  capProviderFor,
  openEncryptor,
  buildEncryptor,
  ownerEnsureKeyring,
  addKeyringRecipientCore,
  addSpaceKeyringRecipient,
  ownerEnsureSpaceKeyring,
  ensureSpaceKeyringRecipient,
  isAlreadyPresentRecipient,
  isKeyringMissing,
  readProfile,
  readProfiles,
  writeProfile,
  ensurePseudo,
  ensureProfileKeys,
  buildAuthHeaders,
} from "./client.js"

// ── Keyed store ────────────────────────────────────────────────────────────────
export { createKeyedStore, createComposedStore } from "./keyed-store.js"

// ── Space access error ────────────────────────────────────────────────────────
export { SpaceAccessError } from "./space-access-error.js"

// ── Space access store ────────────────────────────────────────────────────────
export type { SpaceAccessEntry, SpaceAccessMap, LinkAccessPayload } from "./space-access-store.js"
export {
  configureSpaceAccessStore,
  hydrateSpaceAccessStore,
  getSpaceAccessEntry,
  saveSpaceAccessEntry,
  removeSpaceAccessEntry,
  getNodeAccessEntry,
  saveNodeAccessEntry,
  removeNodeAccessEntry,
  getNodeStreamAccessEntry,
  saveNodeStreamAccessEntry,
  removeNodeStreamAccessEntry,
  getNodeKeyringAccessEntry,
  saveNodeKeyringAccessEntry,
  removeNodeKeyringAccessEntry,
  localSpaceAccessEntries,
  memberCapsFromStore,
  linkAccessFromStore,
  clearSpaceAccessStore,
  clearPersistedSpaceAccess,
} from "./space-access-store.js"

// ── Account seal ──────────────────────────────────────────────────────────────
export { sealToSelf, unsealFromSelf, sealToRecipient, unsealFromRecipient } from "./account-seal.js"

// ── Request verify ────────────────────────────────────────────────────────────
export { signKemSig, verifyKemSig } from "./request-verify.js"

// ── CAS retry ────────────────────────────────────────────────────────────────
export { runCas } from "./cas-retry.js"

// ── Objects (pure tree algorithms) ───────────────────────────────────────────
export {
  buildTree,
  addObject,
  nextOrder,
  breadcrumbs,
  ancestors,
  subtreeIds,
  patchObject,
  reparentObject,
  reorderObjects,
  archiveObject,
} from "./objects.js"
export type { ObjectTreeNode, NewObjectInput } from "./objects.js"

// ── Node keyring ──────────────────────────────────────────────────────────────
export type { NodeKeyringRecipient } from "./node-keyring.js"
export {
  ownerEnsureNodeKeyring,
  openNodeEncryptor,
  buildNodeEncryptor,
  addNodeKeyringRecipient,
  ensureNodeKeyringRecipient,
  removeNodeKeyringRecipient,
} from "./node-keyring.js"

// ── Space access resolver ─────────────────────────────────────────────────────
export type { NodeAccessHandle } from "./space-access.js"
export {
  getSpaceClient,
  getNodeStreamClient,
  getNodeAccess,
  buildNodeAccess,
  clearNodeAccessCache,
} from "./space-access.js"

// ── Token types ───────────────────────────────────────────────────────────────
export type {
  JoinRequest,
  SpaceInviteLinkToken,
  NodeInviteBundle,
  NodeInviteKind,
  NodeInviteLinkToken,
  ResourceRequest,
  ResourceGrant,
  ResourceReject,
  StoredNodeInvite,
} from "./token-types.js"

// ── Invite helpers ────────────────────────────────────────────────────────────
export type { CapSubject } from "./invite-helpers.js"
export {
  adderOf,
  mintCap,
  capNonce,
  parseJoinRequest,
  ephemeralSubject,
  assertCapForMe,
  evictKeyringMember,
} from "./invite-helpers.js"

// ── Registry ──────────────────────────────────────────────────────────────────
export type { SpaceMeta, SpaceMetaUpdate, SpacesDoc, SpaceEntry } from "./registry.js"
export {
  buildSpace,
  onSpaceMeta,
  broadcastSpaceMeta,
  readSpaces,
  updateSpacesDoc,
  updateSpacesExtraField,
  writeSpaces,
  reorderSpaces,
  readSpaceAccess,
  writeSpaceAccess,
  addSpaceMember,
  removeSpaceMember,
  removeJoinedSpace,
  moveSpace,
  addJoinedSpace,
  addJoinedSpaceWithCap,
  addJoinedSpaceWithLinkAccess,
  createSpace,
  reconcileSpaceMeta,
} from "./registry.js"

// ── Object index ──────────────────────────────────────────────────────────────
export { pushIndexSeed, seedSpaceObjectIndex, updateObjectIndex, readObjectTree } from "./object-index.js"

// ── Members ───────────────────────────────────────────────────────────────────
export type { StoredSpaceInvite } from "./members.js"
export {
  makeJoinRequest,
  saveSpaceInviteEntry,
  getSpaceInviteEntry,
  clearSpaceInviteStore,
  serializeSpaceInviteStore,
  hydrateSpaceInviteStore,
  inviteToSpace,
  acceptSpaceInvite,
  encodeSpaceInviteLink,
  decodeSpaceInviteLink,
  createSpaceInviteLink,
  joinSpaceByLink,
  addDeviceToSpaceKeyring,
  recoverSpaceAccess,
  revokeSpaceAccess,
} from "./members.js"

// ── Nodes ─────────────────────────────────────────────────────────────────────
export type { CreateNodeInput } from "./nodes.js"
export {
  saveNodeInviteEntry,
  getNodeInviteEntry,
  clearNodeInviteStore,
  serializeNodeInviteStore,
  hydrateNodeInviteStore,
  createNode,
  setNodeAccess,
  inviteToNode,
  acceptNodeInvite,
  revokeNodeAccess,
  encodeNodeInviteLink,
  decodeNodeInviteLink,
  createNodeInviteLink,
  joinNodeByLink,
  readNodeWithLinkCap,
  writeNodeWithLinkCap,
} from "./nodes.js"

// ── Inbox ─────────────────────────────────────────────────────────────────────
export type { InboxElement } from "./inbox.js"
export { inboxShard, inboxShards, pullInbox } from "./inbox.js"

// ── Identity link ─────────────────────────────────────────────────────────────
export type { IdentityLink } from "./identity-link.js"
export {
  verifyIdentityLinkBinding,
  encodeIdentityLink,
  decodeIdentityLink,
  myIdentityLink,
  verifyIdentityLinkKeys,
} from "./identity-link.js"

// ── Resource requests ─────────────────────────────────────────────────────────
export type { SubmitResourceRequestOptions, PendingRequest, AcceptResult } from "./resource-requests.js"
export {
  saveReqIdOwner,
  serializeReqIdOwnerStore,
  hydrateReqIdOwnerStore,
  clearReqIdOwnerStore,
  submitResourceRequest,
  scanResourceRequests,
  acceptResourceRequest,
  rejectResourceRequest,
  scanResourceGrants,
  scanResourceRejects,
  acceptResourceGrant,
} from "./resource-requests.js"

// ── Object directory ──────────────────────────────────────────────────────────
export type { ObjectDirectoryEntry } from "./object-directory.js"
export { parseObjectDirectoryDoc, readObjectDirectory } from "./object-directory.js"

// ── Vault (platform-agnostic identity persistence) ────────────────────────────
export type {
  DerivedIdentity,
  PersistedSession,
  Vault,
  VaultLoad,
  UnlockMethod,
  PasskeyEnrollment,
  SeedLock,
} from "./vault.js"
export { rootIdentityOf, sessionFromPersisted, activeAccountOf } from "./vault.js"

// ── Plugin (server companion) ─────────────────────────────────────────────────
export type { SpaceObjectStore, DirectoryStore } from "./plugin.js"
export { createSpacesRoleEnricher, createSpacesDirectoryServerPlugin } from "./plugin.js"
