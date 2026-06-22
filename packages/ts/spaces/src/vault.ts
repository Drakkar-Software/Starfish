/**
 * Generic multi-account vault — platform-agnostic identity persistence types
 * and session-rebuild helpers.
 *
 * A Vault holds one or more PersistedSession entries (accounts) plus an
 * `activeId` pointer. Sealing the vault at rest is the caller's responsibility
 * (e.g. via `sealWithPassphrase` from `starfish-identities`, or a native
 * Keychain). This module provides only the shared types and the logic to rebuild
 * a live Session from a persisted entry.
 *
 * sessionFromPersisted receives `clientOpts` explicitly — the caller supplies
 * the connection config (baseUrl, namespace) rather than reading from globals,
 * keeping this module config-source-agnostic.
 */
import type { CapCert } from "@drakkar.software/starfish-protocol"
import type { BootstrapOrigin } from "@drakkar.software/starfish-identities"

import { buildSession, buildLinkedSession, deriveSession } from "./session.js"
import type { Session } from "./session.js"
import type { ClientOpts, DeviceKeys } from "./client.js"

// ── Types ──────────────────────────────────────────────────────────────────────

/**
 * The root identity already derived from the seed (userId + device keys).
 * Caching it lets unlock/cold-start skip the heavy `bootstrapRootIdentity`
 * Argon2id derivation. Same sensitivity as the seed; store inside the same
 * sealed blob.
 */
export interface DerivedIdentity {
  userId: string
  keys: DeviceKeys
}

/**
 * A persisted account entry. The minimum to re-derive (seed) or restore (derived)
 * a live Session.
 */
export interface PersistedSession {
  /** BIP-39 recovery seed. Absent for non-seed origins. */
  seed?: string[]
  name: string
  /** Cached root identity so restore skips the Argon2id derivation. */
  derived?: DerivedIdentity
  /** How this identity was bootstrapped. Absent for seed-derived identities. */
  bootstrapOrigin?: BootstrapOrigin
  /** Root-signed cap-cert for a PAIRED (linked) device. */
  capCert?: CapCert
}

/**
 * All accounts held on this device plus which one is active. Sealed as a unit:
 * web path — one app-lock via a vault master key;
 * native path — a single secure-store / Keychain entry.
 */
export interface Vault {
  accounts: PersistedSession[]
  activeId: string
}

/** Ways a persisted seed can be unlocked (web platform). */
export type UnlockMethod = "pin" | "passkey"

/** A registered passkey credential + the PRF secret used to seal the seed for it. */
export interface PasskeyEnrollment {
  credentialId: string
  salt: string
  secretHex: string
}

/** How to lock the seed when persisting it (web platform). */
export interface SeedLock {
  pin: string
  passkey?: PasskeyEnrollment
}

/**
 * Result of probing storage at launch:
 * - `none`   — nothing stored; start signed-out.
 * - `ready`  — vault available immediately (native Keychain path).
 * - `locked` — a sealed vault exists; unlock with one of `methods` (web path).
 * - `error`  — storage read failed.
 */
export type VaultLoad =
  | { kind: "none" }
  | { kind: "ready"; vault: Vault }
  | { kind: "locked"; methods: UnlockMethod[] }
  | { kind: "error"; error: unknown }

// ── Helpers ────────────────────────────────────────────────────────────────────

/**
 * Extract the root identity (userId + keys) from any session-like object.
 * Useful for populating a {@link DerivedIdentity} cache entry after a fresh
 * `buildSession` or `deriveSession` call.
 */
export function rootIdentityOf(s: { userId: string; keys: DerivedIdentity["keys"] }): DerivedIdentity {
  return { userId: s.userId, keys: s.keys }
}

/**
 * Rebuild a live {@link Session} from a persisted vault entry.
 *
 * Resolution order:
 *  1. `capCert` + `derived` → {@link buildLinkedSession} (paired device, no derivation)
 *  2. `derived` alone        → {@link buildSession}        (skip Argon2id)
 *  3. `seed`                 → {@link deriveSession}        (full derivation)
 *
 * @param p           A persisted account entry from {@link Vault.accounts}.
 * @param clientOpts  Connection parameters: `baseUrl` and `namespace`.
 * @param opts.sharedNamespace  Optional shared-spaces namespace.
 */
export async function sessionFromPersisted(
  p: PersistedSession,
  clientOpts: ClientOpts,
  opts?: { sharedNamespace?: string },
): Promise<Session> {
  const sharedNamespace = opts?.sharedNamespace
  if (p.capCert && p.derived) {
    return buildLinkedSession({
      identity: { userId: p.derived.userId, keys: p.derived.keys, capCert: p.capCert },
      name: p.name,
      clientOpts,
      sharedNamespace,
    })
  }
  if (p.derived) {
    try {
      return await buildSession({
        userId: p.derived.userId,
        keys: p.derived.keys,
        name: p.name,
        clientOpts,
        sharedNamespace,
      })
    } catch {
      /* cached keys unusable — fall through to full re-derivation */
    }
  }
  if (p.seed) return deriveSession(p.seed, clientOpts, { name: p.name, sharedNamespace })
  throw new Error("Persisted account has neither usable derived keys nor a recovery seed.")
}

/** The active account in a vault: the one matching `activeId`, else the first. */
export function activeAccountOf(v: Vault): PersistedSession | null {
  if (v.accounts.length === 0) return null
  return v.accounts.find((a) => a.derived?.userId === v.activeId) ?? v.accounts[0]
}
