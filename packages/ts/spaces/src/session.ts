/**
 * Session abstraction.
 *
 * A `Session` is the root runtime object threaded through all spaces domain
 * calls. It holds the identity (userId + device keys), the pre-built Starfish
 * clients (content, account, spaces-registry, spaces-keyring), and the
 * resolved {@link SpaceLayout} + namespace constants.
 *
 * Build sessions with:
 *  - {@link buildSession} — from a root-derived `(userId, keys)` pair
 *  - {@link buildLinkedSession} — from a paired device's `(userId, keys, capCert)` triple
 *  - {@link deriveSession} — from a 12-word BIP-39 seed phrase (derives the root identity first)
 */
import { generateMnemonic, validateMnemonic } from "@scure/bip39"
import { wordlist } from "@scure/bip39/wordlists/english"
import { bootstrapRootIdentity, mintDeviceCap, computeOwnerTrustedAdders } from "@drakkar.software/starfish-identities"
import type { StarfishClient } from "@drakkar.software/starfish-client"
import type { CapCert } from "@drakkar.software/starfish-protocol"

import type { DeviceKeys } from "./client.js"
import {
  makeSpaceClient,
  ensurePseudo,
  ensureProfileKeys,
  type ClientOpts,
} from "./client.js"
import type { SpaceLayout, SpacesConfig, KvAdapter } from "./config.js"
import { defaultSpaceLayout, defaultUserIdFromEdPub } from "./layout.js"
import { getSpacesConfig } from "./config.js"

// ── Session type ───────────────────────────────────────────────────────────────

export interface Session {
  // ── Identity ───────────────────────────────────────────────────────────────
  userId: string
  name: string
  keys: DeviceKeys
  contentCap: unknown
  accountCap: unknown

  // ── Pre-built clients ──────────────────────────────────────────────────────
  /** Primary client for space content (keyrings, nodes, objects). */
  contentClient: StarfishClient
  /** Client for account-scoped docs (profile, `_spaces` registry). */
  accountClient: StarfishClient
  /**
   * Client for the cross-app spaces registry. Equals `accountClient` when no
   * shared-spaces namespace override is configured.
   */
  spacesRegistryClient: StarfishClient
  /**
   * Client for cross-app space-keyring operations. Equals `contentClient`
   * when no shared-spaces namespace override is configured.
   */
  spacesKeyringClient: StarfishClient

  // ── Display metadata ───────────────────────────────────────────────────────
  fingerprint: string
  /**
   * The Ed25519 pubkey that OWNS this session's spaces (used as the trusted-adder
   * anchor for the space-wide keyring). For the root device this is `keys.edPub`;
   * for a linked device it is the issuer's edPub from the cap-cert.
   */
  ownerEdPub: string

  // ── Resolved configuration (injected at build time) ────────────────────────
  layout: SpaceLayout
  userIdFromEdPub: (edPubHex: string) => Promise<string>
  spaceIdPrefix: string
  nodeIdPrefix: string
  inboxAadNamespace: string
  kvKeyPrefix: string
  kvAdapter?: KvAdapter

  // ── Raw server coordinates (for raw-fetch helpers) ─────────────────────────
  baseUrl: string
  namespace: string
}

// ── Build helpers ──────────────────────────────────────────────────────────────

function resolveConfig(cfg: SpacesConfig) {
  return {
    layout: cfg.layout ?? defaultSpaceLayout,
    userIdFromEdPub: cfg.userIdFromEdPub ?? defaultUserIdFromEdPub,
    spaceIdPrefix: cfg.spaceIdPrefix ?? "sp-",
    nodeIdPrefix: cfg.nodeIdPrefix ?? "obj-",
    inboxAadNamespace: cfg.inboxAadNamespace ?? "octospaces:inbox:v1",
    kvKeyPrefix: cfg.kvKeyPrefix ?? "octospaces.spaceaccess.",
    kvAdapter: cfg.kvAdapter,
  }
}

/** Human-readable fingerprint from a userId hex string. */
export function fingerprintFromUserId(userId: string): string {
  const h = userId.replace(/[^0-9a-f]/gi, "").toUpperCase()
  return [h.slice(0, 4), h.slice(4, 8), h.slice(8, 12)].filter(Boolean).join(" · ")
}

/** Fresh 12-word recovery seed. */
export function generateSeedWords(): string[] {
  return generateMnemonic(wordlist, 128).split(" ")
}

/** True when `words` is a valid BIP-39 mnemonic. */
export function isValidSeed(words: string[]): boolean {
  return validateMnemonic(words.join(" ").trim(), wordlist)
}

/** Trusted-adder allow-list for opening an OWNED space's keyring. */
export function ownerTrustedAdders(session: Session): string[] {
  return computeOwnerTrustedAdders(session.ownerEdPub, session.keys.edPub)
}

export interface BuildSessionOpts {
  /** Already-derived identity (userId + device keys). */
  userId: string
  keys: DeviceKeys
  name?: string
  /** Connection parameters — baseUrl + namespace + optional fetch tuning. */
  clientOpts: ClientOpts
  /** Optional shared-spaces namespace (a separate namespace for cross-app spaces). */
  sharedNamespace?: string
  /** Config overrides (layout, constants). Falls back to module-level config from `configureSpaces()`. */
  config?: SpacesConfig
}

/**
 * Build a full owner session from a root-derived `(userId, keys)` pair.
 * Mints two device caps (owner + account), constructs four clients.
 */
export async function buildSession({
  userId,
  keys,
  name,
  clientOpts,
  sharedNamespace,
  config,
}: BuildSessionOpts): Promise<Session> {
  const cfg = resolveConfig({ ...getSpacesConfig(), ...config })
  const layout = cfg.layout
  const sub = { edPubHex: keys.edPub, kemPubHex: keys.kemPub }
  const contentCap = await mintDeviceCap(keys.edPriv, keys.edPub, sub, layout.ownerScope())
  const accountCap = await mintDeviceCap(keys.edPriv, keys.edPub, sub, layout.accountScope(userId))

  const contentClient = makeSpaceClient(contentCap, keys.edPriv, clientOpts)
  const accountClient = makeSpaceClient(accountCap, keys.edPriv, clientOpts)

  const sharedContentOpts = sharedNamespace ? { ...clientOpts, namespace: sharedNamespace } : clientOpts
  const spacesRegistryClient = sharedNamespace
    ? makeSpaceClient(accountCap, keys.edPriv, sharedContentOpts)
    : accountClient
  const spacesKeyringClient = sharedNamespace
    ? makeSpaceClient(contentCap, keys.edPriv, sharedContentOpts)
    : contentClient

  const fallback = name?.trim() || `user-${userId.slice(0, 6)}`
  const displayName = await ensurePseudo(accountClient, userId, layout, fallback).catch(() => fallback)
  void ensureProfileKeys(accountClient, userId, layout, keys).catch(() => {})

  return {
    userId,
    name: displayName,
    keys,
    contentCap,
    accountCap,
    contentClient,
    accountClient,
    spacesRegistryClient,
    spacesKeyringClient,
    fingerprint: fingerprintFromUserId(userId),
    ownerEdPub: keys.edPub,
    layout,
    userIdFromEdPub: cfg.userIdFromEdPub,
    spaceIdPrefix: cfg.spaceIdPrefix,
    nodeIdPrefix: cfg.nodeIdPrefix,
    inboxAadNamespace: cfg.inboxAadNamespace,
    kvKeyPrefix: cfg.kvKeyPrefix,
    kvAdapter: cfg.kvAdapter,
    baseUrl: clientOpts.baseUrl,
    namespace: clientOpts.namespace,
  }
}

/** A paired device's credentials: its own keypair + the root-signed cap-cert. */
export interface LinkedIdentity {
  userId: string
  keys: DeviceKeys
  capCert: CapCert
}

export interface BuildLinkedSessionOpts {
  identity: LinkedIdentity
  name?: string
  clientOpts: ClientOpts
  sharedNamespace?: string
  config?: SpacesConfig
}

/**
 * Build a session for a paired (linked) device. The device keypair is NOT the
 * root, so it cannot self-mint caps — all four clients use the root-signed
 * `capCert` from the pairing bundle.
 */
export async function buildLinkedSession({
  identity: { userId, keys, capCert },
  name,
  clientOpts,
  sharedNamespace,
  config,
}: BuildLinkedSessionOpts): Promise<Session> {
  const cfg = resolveConfig({ ...getSpacesConfig(), ...config })
  const layout = cfg.layout

  const contentClient = makeSpaceClient(capCert, keys.edPriv, clientOpts)
  const accountClient = makeSpaceClient(capCert, keys.edPriv, clientOpts)

  const sharedContentOpts = sharedNamespace ? { ...clientOpts, namespace: sharedNamespace } : clientOpts
  const spacesRegistryClient = sharedNamespace
    ? makeSpaceClient(capCert, keys.edPriv, sharedContentOpts)
    : accountClient
  const spacesKeyringClient = sharedNamespace
    ? makeSpaceClient(capCert, keys.edPriv, sharedContentOpts)
    : contentClient

  const fallback = name?.trim() || `user-${userId.slice(0, 6)}`
  const displayName = await ensurePseudo(accountClient, userId, layout, fallback).catch(() => fallback)

  return {
    userId,
    name: displayName,
    keys,
    contentCap: capCert,
    accountCap: capCert,
    contentClient,
    accountClient,
    spacesRegistryClient,
    spacesKeyringClient,
    fingerprint: fingerprintFromUserId(userId),
    ownerEdPub: capCert.iss,
    layout,
    userIdFromEdPub: cfg.userIdFromEdPub,
    spaceIdPrefix: cfg.spaceIdPrefix,
    nodeIdPrefix: cfg.nodeIdPrefix,
    inboxAadNamespace: cfg.inboxAadNamespace,
    kvKeyPrefix: cfg.kvKeyPrefix,
    kvAdapter: cfg.kvAdapter,
    baseUrl: clientOpts.baseUrl,
    namespace: clientOpts.namespace,
  }
}

/**
 * Derive a full owner session from a 12-word BIP-39 seed phrase.
 * Runs `bootstrapRootIdentity` (Argon2id — slow) to derive the root identity,
 * then calls {@link buildSession}.
 */
export async function deriveSession(
  seedWords: string[],
  clientOpts: ClientOpts,
  opts?: { name?: string; sharedNamespace?: string; config?: SpacesConfig },
): Promise<Session> {
  const passphrase = seedWords.join(" ").trim()
  const creds = await bootstrapRootIdentity(passphrase)
  return buildSession({
    userId: creds.userId,
    keys: creds.device as DeviceKeys,
    name: opts?.name,
    clientOpts,
    sharedNamespace: opts?.sharedNamespace,
    config: opts?.config,
  })
}
