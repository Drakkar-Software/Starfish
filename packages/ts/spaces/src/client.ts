/**
 * Starfish client construction + space keyring/encryptor helpers.
 *
 * Server coordinates (baseUrl, namespace) are injected through `ClientOpts`
 * rather than read from a global config module — call `makeSpaceClient` /
 * `makeAnonSpaceClient` with the connection parameters your app has already
 * resolved.
 */
import { StarfishClient, StarfishHttpError, createKvPullCache } from "@drakkar.software/starfish-client"
import type { BatchPullEntry, Encryptor, StarfishCapProvider, StarfishClientOptions } from "@drakkar.software/starfish-client"
import { addCollectionRecipient, createKeyring, createKeyringEncryptor } from "@drakkar.software/starfish-keyring"
import type { Keyring } from "@drakkar.software/starfish-keyring"
import { signRequest, stableStringify } from "@drakkar.software/starfish-protocol"
import type { SignableMethod } from "@drakkar.software/starfish-protocol"

import { SpaceAccessError } from "./space-access-error.js"
import { NodeAccessRevokedError } from "./node-access-revoked-error.js"
import { runCas } from "./cas-retry.js"
import { getCachedDoc, noteHash } from "./doc-cache.js"
import { signKemSig } from "./request-verify.js"
import { computeOwnerTrustedAdders } from "@drakkar.software/starfish-identities"
import type { SpaceLayout } from "./config.js"
import { getSpacesConfig } from "./config.js"

// ── DeviceKeys ─────────────────────────────────────────────────────────────────

/** The four-hex-key bundle for a device (Ed25519 + X25519). */
export interface DeviceKeys {
  edPriv: string
  edPub: string
  kemPriv: string
  kemPub: string
}

// ── Client construction ────────────────────────────────────────────────────────

/**
 * TTL for the read-through pull cache built from the configured `kvAdapter`.
 * 30 days matches the example in the `createKvPullCache` documentation and is
 * long enough to survive any reasonable reload cycle (device sleep, offline use).
 */
const CACHE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000

/**
 * Return a `PullCache` backed by the configured `kvAdapter`, or `undefined`
 * when none has been installed via {@link configureSpaces}. Called lazily per
 * client so the cache reflects the kvAdapter active at construction time.
 */
function defaultPullCache(): StarfishClientOptions["cache"] | undefined {
  const kv = getSpacesConfig().kvAdapter
  return kv ? createKvPullCache(kv, { maxAgeMs: CACHE_MAX_AGE_MS }) : undefined
}

/** Connection parameters for building a Starfish client. */
export interface ClientOpts {
  baseUrl: string
  namespace: string
  /** Optional fetch override (e.g. timeout wrapper). */
  fetch?: typeof globalThis.fetch
  /** Optional pull-cache adapter. */
  cache?: StarfishClientOptions["cache"]
  cacheMaxAgeMs?: number
  cacheFallbackStatuses?: number[]
  /** Called after a background revalidation delivers a fresh snapshot.
   *  Receives the namespaced document path and the fresh `PullResult` —
   *  use it to re-run any hydration (caps, mutes, reads) that depends on the
   *  `_spaces` doc when the staleWhileRevalidate background fetch completes. */
  onRevalidated?: StarfishClientOptions["onRevalidated"]
}

export function capProviderFor(cap: unknown, devEdPrivHex: string): StarfishCapProvider {
  return {
    async getCap() {
      return { cap: cap as never, devEdPrivHex }
    },
  }
}

/** Build an authenticated Starfish client from a cap + device key. */
export function makeSpaceClient(cap: unknown, devEdPrivHex: string, opts: ClientOpts): StarfishClient {
  return new StarfishClient({
    baseUrl: opts.baseUrl,
    namespace: opts.namespace,
    capProvider: capProviderFor(cap, devEdPrivHex),
    fetch: opts.fetch,
    // Use caller-supplied cache when provided; fall back to a cache built from the
    // module-level kvAdapter (installed via configureSpaces) so push/pull results
    // survive a tab reload and makeHandle.push / updateObjectIndex can seed their
    // in-memory doc-cache from peekCache without an extra network pull.
    cache: opts.cache ?? defaultPullCache(),
    cacheMaxAgeMs: opts.cacheMaxAgeMs,
    cacheFallbackStatuses: opts.cacheFallbackStatuses,
    onRevalidated: opts.onRevalidated,
  })
}

/** Build a cap-less (anonymous) Starfish client for public reads/writes. */
export function makeAnonSpaceClient(opts: Pick<ClientOpts, "baseUrl" | "namespace" | "fetch">): StarfishClient {
  return new StarfishClient({
    baseUrl: opts.baseUrl,
    namespace: opts.namespace,
    fetch: opts.fetch,
  })
}

// ── Keyring encryptor helpers ──────────────────────────────────────────────────

/**
 * Open a node's decryptor from the server-side keyring doc.
 * Throws `SpaceAccessError` on access denial; any other error indicates
 * a transient network / server failure.
 */
export async function openEncryptor(
  client: StarfishClient,
  keys: DeviceKeys,
  keyringPullPath: string,
  trustedAdders: string[],
): Promise<Encryptor> {
  const res = await client.pull(keyringPullPath).catch((err: unknown) => {
    if (err instanceof StarfishHttpError) throw err
    throw new Error("Could not reach the server to fetch node keys.")
  })
  const keyring = res?.data as unknown as Keyring | undefined
  if (!keyring || !keyring.epochs) {
    throw new SpaceAccessError("", undefined, "This node has no keyring yet — ask the owner to create it first.")
  }
  try {
    const enc = await createKeyringEncryptor(
      keyring,
      { kemPubHex: keys.kemPub, kemPrivHex: keys.kemPriv },
      { trustedAdders },
    )
    return enc as unknown as Encryptor
  } catch {
    throw new SpaceAccessError(
      "",
      undefined,
      "You're not a recipient of this node's keyring — ask the owner to invite you.",
    )
  }
}

/** Soft variant of {@link openEncryptor}: returns `null` instead of throwing.
 *
 * Exception: when the server responds with 403, throws `NodeAccessRevokedError`
 * instead of returning `null` — a 403 is a definitive revocation signal, not a
 * transient "not yet available" state, and callers must handle it explicitly.
 */
export async function buildEncryptor(
  client: StarfishClient,
  keys: DeviceKeys,
  keyringPullPath: string,
  trustedAdders: string[],
  spaceId?: string,
  nodeId?: string,
): Promise<Encryptor | null> {
  try {
    return await openEncryptor(client, keys, keyringPullPath, trustedAdders)
  } catch (err: unknown) {
    if (err instanceof StarfishHttpError && err.status === 403) {
      throw new NodeAccessRevokedError(spaceId ?? "", nodeId ?? "")
    }
    return null
  }
}

/**
 * Owner-side: create a per-node keyring if missing, then return an encryptor.
 * Uses runCas to survive concurrent creates from multiple devices.
 * On a 409, runCas re-pulls; if the concurrent create landed first, the re-pull
 * returns the existing keyring and we skip the create block — same as a successful open.
 */
export async function ownerEnsureKeyring(
  client: StarfishClient,
  keys: DeviceKeys,
  keyringPullPath: string,
  keyringPushPath: string,
  trustedAdders: string[] = [keys.edPub],
): Promise<Encryptor> {
  return runCas(async ({ currentHash }) => {
    const krRes = await client.pull(keyringPullPath).catch(() => null)
    let keyring = krRes?.data as unknown as Keyring | undefined
    let baseHash = krRes?.hash || ""
    // Cold/degraded pull (e.g. after a tab reload where the server returns hash:""): recover
    // the keyring from the persistent read-through cache instead of destructively re-creating
    // it. The keyring envelope is server-plaintext (KEM-wrapped keys inside), so reading its
    // data from the cache is safe. Without this, the re-create branch below would 409 on the
    // first attempt and — on the runCas retry when currentHash is set — could overwrite the
    // real keyring with an empty one (member lockout / data loss).
    if (!keyring || !keyring.epochs) {
      const peeked = await client.peekCache(keyringPullPath).catch(() => null)
      const pk = peeked?.data as unknown as Keyring | undefined
      if (pk?.epochs) {
        keyring = pk
        baseHash = baseHash || peeked?.hash || ""
        if (peeked?.hash) noteHash(keyringPushPath, peeked.hash)
      }
    }
    if (!keyring || !keyring.epochs) {
      const created = await createKeyring({ edPrivHex: keys.edPriv, edPubHex: keys.edPub }, [
        { subKemHex: keys.kemPub },
      ])
      keyring = created.keyring
      // Never push null/empty hash — use authoritative conflict hash or cache fallback.
      const bh = baseHash || currentHash || getCachedDoc(keyringPushPath)?.hash || ""
      const pushRes = await client.push(keyringPushPath, keyring as unknown as Record<string, unknown>, bh)
      noteHash(keyringPushPath, pushRes.hash)
    }
    const enc = await createKeyringEncryptor(
      keyring,
      { kemPubHex: keys.kemPub, kemPrivHex: keys.kemPriv },
      { trustedAdders },
    )
    return enc as unknown as Encryptor
  })
}

/** True when the error indicates the recipient is already present (idempotent). */
export function isAlreadyPresentRecipient(err: unknown): boolean {
  return /already (present|a recipient|exists)|duplicate/i.test(err instanceof Error ? err.message : String(err))
}

/** True when the error indicates the keyring doesn't exist yet (benign during device pairing). */
export function isKeyringMissing(err: unknown): boolean {
  return err instanceof Error && /not found|404|does not exist|no keyring/i.test(err.message)
}

/**
 * Add a recipient to a keyring collection. Swallows "already present" so
 * re-inviting the same KEM is idempotent.
 */
export async function addKeyringRecipientCore(
  client: StarfishClient,
  keys: DeviceKeys,
  collection: string,
  recipient: { subKem: string; userId?: string; label?: string },
  trustedAdders: string[],
): Promise<void> {
  try {
    await addCollectionRecipient(
      client,
      collection,
      recipient,
      { edPriv: keys.edPriv, edPub: keys.edPub, kemPriv: keys.kemPriv },
      { trustedAdders },
    )
  } catch (err) {
    if (!isAlreadyPresentRecipient(err)) throw err
  }
}

/** Add a recipient to a space's keyring. Swallows "already present". */
export function addSpaceKeyringRecipient(
  session: { spacesKeyringClient: StarfishClient; keys: DeviceKeys; ownerEdPub?: string; layout: SpaceLayout },
  spaceId: string,
  recipient: { subKem: string; userId: string; label: string },
): Promise<void> {
  return addKeyringRecipientCore(
    session.spacesKeyringClient,
    session.keys,
    session.layout.keyringName(spaceId),
    recipient,
    computeOwnerTrustedAdders(session.ownerEdPub, session.keys.edPub),
  )
}

type SpaceKeyringSession = {
  spacesKeyringClient: StarfishClient
  keys: DeviceKeys
  ownerEdPub?: string
  layout: SpaceLayout
}

/** Create the space keyring if absent, then return the owner's encryptor. */
export function ownerEnsureSpaceKeyring(session: SpaceKeyringSession, spaceId: string): Promise<Encryptor> {
  const trustedAdders = computeOwnerTrustedAdders(session.ownerEdPub, session.keys.edPub)
  return ownerEnsureKeyring(
    session.spacesKeyringClient,
    session.keys,
    session.layout.keyringPull(spaceId),
    session.layout.keyringPush(spaceId),
    trustedAdders,
  )
}

/** Ensure the space keyring exists, then add a recipient. Returns the owner's encryptor. */
export async function ensureSpaceKeyringRecipient(
  session: SpaceKeyringSession,
  spaceId: string,
  recipient: { subKem: string; userId: string; label: string },
): Promise<Encryptor> {
  const enc = await ownerEnsureSpaceKeyring(session, spaceId)
  await addSpaceKeyringRecipient(session, spaceId, recipient)
  return enc
}

// ── Profile helpers ────────────────────────────────────────────────────────────

/** A user's public profile. */
export interface PublicProfile {
  pseudo: string | null
  avatar: string | null
  edPub: string | null
  kemPub: string | null
  kemSig: string | null
}

function coerceProfile(data: Record<string, unknown> | null): PublicProfile {
  return {
    pseudo: typeof data?.pseudo === "string" ? data.pseudo : null,
    avatar: typeof data?.avatar === "string" ? data.avatar : null,
    edPub: typeof data?.edPub === "string" ? data.edPub : null,
    kemPub: typeof data?.kemPub === "string" ? data.kemPub : null,
    kemSig: typeof data?.kemSig === "string" ? data.kemSig : null,
  }
}

async function fetchProfileRaw(
  baseUrl: string,
  pullPath: string,
  fetchFn = globalThis.fetch,
): Promise<{ status: number; ok: boolean; data: Record<string, unknown> | null }> {
  const r = await fetchFn(`${baseUrl}${pullPath}`)
  if (!r.ok) return { status: r.status, ok: false, data: null }
  const body = await r.json()
  return { status: r.status, ok: true, data: (body?.data ?? null) as Record<string, unknown> | null }
}

/** Read a user's public profile (pseudo, avatar, public identity keys). */
export async function readProfile(
  userId: string,
  opts: { baseUrl: string; layout: SpaceLayout; fetch?: typeof globalThis.fetch },
): Promise<PublicProfile> {
  try {
    const info = await fetchProfileRaw(opts.baseUrl, opts.layout.profilePull(userId), opts.fetch)
    if (!info.ok) return coerceProfile(null)
    return coerceProfile(info.data)
  } catch {
    return coerceProfile(null)
  }
}

const PROFILE_BATCH_CHUNK = 24

/** Read multiple users' public profiles in batched `/batch/pull` round-trips. */
export async function readProfiles(
  ids: string[],
  opts: { baseUrl: string; namespace: string; fetch?: typeof globalThis.fetch; layout: SpaceLayout },
): Promise<Map<string, PublicProfile>> {
  const out = new Map<string, PublicProfile>()
  const client = makeAnonSpaceClient({ baseUrl: opts.baseUrl, namespace: opts.namespace, fetch: opts.fetch })
  for (let i = 0; i < ids.length; i += PROFILE_BATCH_CHUNK) {
    const chunk = ids.slice(i, i + PROFILE_BATCH_CHUNK)
    let entries: BatchPullEntry[]
    try {
      entries = await client.batchPullMany("profile", chunk.map((id) => ({ identity: id })))
    } catch {
      continue
    }
    chunk.forEach((id, j) => {
      const entry = entries[j]
      if (!entry || entry.error) return
      const profile = coerceProfile((entry.data ?? null) as Record<string, unknown> | null)
      out.set(id, profile)
    })
  }
  return out
}

/**
 * Merge a patch into the caller's own profile doc.
 * Wrapped in `runCas` + `peekCache` seed so a degraded live pull (hash:"") doesn't
 * drop existing fields (avatar/keys) and doesn't push a stale `baseHash` → 409.
 */
export async function writeProfile(
  client: StarfishClient,
  userId: string,
  layout: SpaceLayout,
  patch: { pseudo?: string; avatar?: string | null; edPub?: string; kemPub?: string; kemSig?: string },
): Promise<void> {
  const pullPath = layout.profilePull(userId)
  const pushPath = layout.profilePush(userId)
  await runCas(async ({ currentHash }) => {
    const current = await client.pull(pullPath).catch(() => null)
    let data = current?.data as Record<string, unknown> | undefined
    let baseHash = current?.hash || currentHash || ""
    if ((!data || !current?.hash) && !currentHash && typeof client.peekCache === "function") {
      // Cold/degraded pull: recover the last-good data+hash from the persistent cache.
      const peeked = await client.peekCache(pullPath).catch(() => null)
      if (peeked?.hash && peeked.data) {
        data = peeked.data as Record<string, unknown>
        baseHash = baseHash || peeked.hash
      }
    }
    const next: Record<string, unknown> = { ...(data ?? {}), ...patch, v: 1 }
    if (next.avatar == null) delete next.avatar
    const pushRes = await client.push(pushPath, next, baseHash)
    noteHash(pushPath, pushRes.hash)
  })
}

/**
 * Seed the caller's profile pseudo only when none exists yet.
 * Consults `peekCache` before concluding the pseudo is absent, so a degraded pull
 * doesn't trigger a destructive overwrite with the fallback value.
 */
export async function ensurePseudo(
  client: StarfishClient,
  userId: string,
  layout: SpaceLayout,
  fallback: string,
): Promise<string> {
  try {
    const pullPath = layout.profilePull(userId)
    const res = await client.pull(pullPath).catch(() => null)
    let data = (res?.data ?? null) as Record<string, unknown> | null
    // Degraded pull (hash:""): check the persistent cache before treating pseudo as absent.
    if ((!data || !res?.hash) && typeof client.peekCache === "function") {
      const peeked = await client.peekCache(pullPath).catch(() => null)
      if (peeked?.hash && peeked.data) data = peeked.data as Record<string, unknown>
    }
    const existing = typeof data?.pseudo === "string" ? data.pseudo.trim() : null
    if (existing) return existing
    await writeProfile(client, userId, layout, { pseudo: fallback })
    return fallback
  } catch {
    return fallback
  }
}

/**
 * Publish this identity's public Ed + KEM keys in its profile (one-time, idempotent).
 * Also writes `kemSig` so paired devices can include it in their identity links.
 * Consults `peekCache` before deciding keys are absent, so a degraded pull doesn't
 * re-publish keys over an already-populated profile.
 */
export async function ensureProfileKeys(
  client: StarfishClient,
  userId: string,
  layout: SpaceLayout,
  keys: { edPub: string; kemPub: string; edPriv: string },
): Promise<void> {
  try {
    const pullPath = layout.profilePull(userId)
    const res = await client.pull(pullPath).catch(() => null)
    let data = (res?.data ?? null) as Record<string, unknown> | null
    // Degraded pull (hash:""): check the persistent cache before deciding keys are absent.
    if ((!data || !res?.hash) && typeof client.peekCache === "function") {
      const peeked = await client.peekCache(pullPath).catch(() => null)
      if (peeked?.hash && peeked.data) data = peeked.data as Record<string, unknown>
    }
    if (data && typeof data.edPub === "string" && typeof data.kemPub === "string") return
    const kemSig = signKemSig(keys)
    await writeProfile(client, userId, layout, { edPub: keys.edPub, kemPub: keys.kemPub, kemSig })
  } catch {
    // Best-effort: profile key publication is not critical for sync
  }
}

// ── Auth headers for raw fetch ─────────────────────────────────────────────────

/**
 * Build cap-cert auth headers for raw `fetch` calls outside StarfishClient.
 */
export async function buildAuthHeaders(
  cap: unknown,
  devEdPrivHex: string,
  method: string,
  pathAndQuery: string,
  host = "",
  body?: Uint8Array | string,
): Promise<Record<string, string>> {
  const { sig, ts, nonce } = await signRequest(
    { method: method as SignableMethod, pathAndQuery, host, body },
    devEdPrivHex,
  )
  const capJson = stableStringify(cap as Record<string, unknown>)
  const capB64 = btoa(capJson)
  return {
    Authorization: `Cap ${capB64}`,
    "X-Starfish-Sig": sig,
    "X-Starfish-Ts": String(ts),
    "X-Starfish-Nonce": nonce,
  }
}
