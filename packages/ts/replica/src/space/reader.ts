/**
 * Session-less read side of a space mirror, one reader per storage tier:
 * `readSpaceMirror` (the space's ONE keyring, from a member cap),
 * `readIsolatedSpaceMirror` (a keyring per node, from per-node grants) and
 * `readPublicSpaceMirror` (no cap, no keyring at all). See
 * `website/docs/extensions/replica.md`.
 *
 * Deliberately independent of `Session`/`SpacePort` (./port.ts): a grant holder
 * is NOT a space member with a wallet, just someone holding a cap-cert and an
 * ephemeral keypair. This is the one place in `./space` that builds its own
 * `StarfishClient`.
 */
import { StarfishClient } from "@drakkar.software/starfish-client"
import type { CapCert } from "@drakkar.software/starfish-protocol"
import { createKeyringEncryptor, type Keyring } from "@drakkar.software/starfish-keyring"
import { makeAnonSpaceClient, parseObjectDirectoryDoc } from "@drakkar.software/starfish-spaces"

/** What `createKeyringEncryptor` hands back — named here so the lazily
 *  memoized keyring promise below has a type without re-deriving it inline. */
type KeyringEncryptor = Awaited<ReturnType<typeof createKeyringEncryptor>>

/** Rendezvous + credentials every cap-holding reader takes. */
interface CapReaderOptions {
  rendezvous: { baseUrl: string; namespace: string }
  /** The grant holder's own ephemeral Ed25519 private key (hex) — every cap it
   *  presents was minted for exactly this device's pubkey. */
  devEdPrivHex: string
  fetch?: typeof fetch
}

/** A client bound to ONE cap: a session-less reader never refreshes or
 *  rotates, it just proves possession of that grant on every request. */
function capClient(opts: CapReaderOptions, cap: CapCert): StarfishClient {
  return new StarfishClient({
    baseUrl: opts.rendezvous.baseUrl,
    namespace: opts.rendezvous.namespace,
    fetch: opts.fetch ?? globalThis.fetch,
    capProvider: { getCap: async () => ({ cap, devEdPrivHex: opts.devEdPrivHex }) },
  })
}

/** Pull one document by bare path; the transport may hand the body back as a
 *  JSON string rather than parsed. */
async function pullJson(client: StarfishClient, path: string): Promise<unknown> {
  const { data } = await client.pull(`/pull/${path}`)
  return typeof data === "string" ? JSON.parse(data) : data
}

function isSealed(doc: unknown): doc is { _encrypted: string; _epoch?: number } {
  return !!doc && typeof doc === "object" && "_encrypted" in doc
}

function isKeyringDoc(doc: unknown): doc is Keyring {
  return !!doc && typeof doc === "object" && !!(doc as { epochs?: unknown }).epochs
}

// Hand-duplicated from `starfish-spaces`' `defaultSpaceLayout`: a session-less
// reader has no `Session`, hence no `session.layout`, to resolve them through.

function objectIndexPath(spaceId: string): string {
  return `spaces/${spaceId}/objects/_index`
}

/** A space's ONE keyring doc. */
function spaceKeyringPath(spaceId: string): string {
  return `spaces/${spaceId}/_keyring`
}

/** One shard of the global public-object directory. */
function objectDirectoryPath(shard: string): string {
  return `_index/objects/${shard}`
}

/** ONE node's own keyring (the isolated tier). */
function nodeKeyringPath(spaceId: string, nodeId: string): string {
  return `spaces/${spaceId}/objects/n/${nodeId}/_keyring`
}

interface ObjectIndexNode {
  id: string
  type: string
}

export interface ReadSpaceMirrorOptions extends CapReaderOptions {
  spaceId: string
  /** A read-only member cap for the space, minted via `inviteToSpace`. Its
   *  `devEdPrivHex` (above) is the device pubkey it was minted for. */
  cap: CapCert
  /** The grant holder's own ephemeral X25519 KEM private key (hex) —
   *  `inviteToSpace` added this device's KEM pubkey as a recipient of the
   *  space's ONE keyring; this is what lets this reader open that keyring
   *  itself (node content is sealed under it, not under the cap). */
  devKemPrivHex: string
  /** Which object-index nodes this reader recognizes as mirror content —
   *  everything else in the space's tree is ignored. */
  isKnownCollection: (type: string) => boolean
  /** Same bare-path template `SpaceMirrorChannel` was configured with; its
   *  collection-id argument is the node's `type` here, exactly as on the
   *  channel's clear path, so ONE literal serves the writer and every reader. */
  docPath: (collectionId: string, spaceId: string, nodeId: string) => string
}

/**
 * Pull and decrypt every node in `opts.spaceId`'s object index that
 * `opts.isKnownCollection` recognizes. A REAL live read, not a point-in-time
 * export. A collection disabled since the grant was minted simply won't appear
 * (its node was cleared, not deleted), so this reflects CURRENT state.
 */
export async function readSpaceMirror(
  opts: ReadSpaceMirrorOptions,
): Promise<Record<string, unknown>> {
  const client = capClient(opts, opts.cap)

  const indexDoc = await pullJson(client, objectIndexPath(opts.spaceId))
  const nodes: ObjectIndexNode[] = Array.isArray((indexDoc as { objects?: unknown })?.objects)
    ? (indexDoc as { objects: ObjectIndexNode[] }).objects
    : []
  const mirrorNodes = nodes.filter((node) => opts.isKnownCollection(node.type))
  const result: Record<string, unknown> = {}
  if (mirrorNodes.length === 0) return result

  // Node content is sealed under the space's ONE keyring, not under the cap.
  // `cap.iss` is the space owner's root edPub, the only trusted adder a
  // session-less reader can name.
  //
  // LAZY: an all-PUBLIC-tier space never mints a keyring, so an up-front pull
  // would turn a space this reader can read in full into a hard throw.
  // Memoized on the in-flight promise, not the resolved value, or the
  // concurrent pulls below would race into two keyring pulls.
  let keyringPull: Promise<KeyringEncryptor> | null = null
  function openKeyring(): Promise<KeyringEncryptor> {
    keyringPull ??= (async () => {
      const keyringDoc = await pullJson(client, spaceKeyringPath(opts.spaceId))
      if (!isKeyringDoc(keyringDoc)) {
        throw new Error("readSpaceMirror: this space has no keyring yet — ask the owner to sync at least once")
      }
      return createKeyringEncryptor(
        keyringDoc,
        { kemPubHex: opts.cap.subKem ?? "", kemPrivHex: opts.devKemPrivHex },
        { trustedAdders: [opts.cap.iss] },
      )
    })()
    return keyringPull
  }

  await Promise.all(
    mirrorNodes.map(async (node) => {
      const sealed = await pullJson(client, opts.docPath(node.type, opts.spaceId, node.id))
      if (!isSealed(sealed)) {
        result[node.type] = sealed ?? {}
        return
      }
      const encryptor = await openKeyring()
      result[node.type] = await encryptor.decrypt(sealed)
    }),
  )
  return result
}

// ── Isolated tier ──────────────────────────────────────────────────────────────

/** One isolated node a grant covers. The caps are the two `inviteToNode(...,
 *  {isolated: true})` mints: `contentCap` (`objinv`) fetches the document,
 *  `keyringCap` (`nodekeyring`) fetches the key to open it. */
export interface IsolatedMirrorNodeGrant {
  /** The node's `type` in the object index. Carried by the grant because
   *  `objindex` is `space:member`, unreadable to a per-node grant holder. */
  collectionId: string
  nodeId: string
  contentCap: CapCert
  keyringCap: CapCert
}

export interface ReadIsolatedSpaceMirrorOptions extends CapReaderOptions {
  spaceId: string
  /** Exactly the nodes this grant covers — no enumeration step, because a
   *  per-node grant holder is not on the space roster and cannot list. */
  nodes: readonly IsolatedMirrorNodeGrant[]
  /** The grant holder's own ephemeral X25519 KEM private key (hex) — added as
   *  a recipient of each node's OWN keyring at invite time. */
  devKemPrivHex: string
  /** Same bare-path template the writer was configured with. */
  docPath: (collectionId: string, spaceId: string, nodeId: string) => string
}

/**
 * Pull and decrypt each node an isolated grant names, every one through its
 * own keyring. No object-index pull (`objindex` is `space:member` and an
 * isolated grant holder never joins the roster) and no shared keyring, so
 * revoking one node leaves the others readable.
 *
 * A node whose content or keyring pull fails is OMITTED rather than failing
 * the batch: with per-node grants, one revoked node is a normal state.
 */
export async function readIsolatedSpaceMirror(
  opts: ReadIsolatedSpaceMirrorOptions,
): Promise<Record<string, unknown>> {
  const result: Record<string, unknown> = {}
  await Promise.all(
    opts.nodes.map(async (node) => {
      try {
        const sealed = await pullJson(
          capClient(opts, node.contentCap),
          opts.docPath(node.collectionId, opts.spaceId, node.nodeId),
        )
        if (!isSealed(sealed)) {
          if (sealed && typeof sealed === "object") result[node.collectionId] = sealed
          return
        }
        const keyringDoc = await pullJson(
          capClient(opts, node.keyringCap),
          nodeKeyringPath(opts.spaceId, node.nodeId),
        )
        if (!isKeyringDoc(keyringDoc)) return
        const encryptor = await createKeyringEncryptor(
          keyringDoc,
          { kemPubHex: node.keyringCap.subKem ?? "", kemPrivHex: opts.devKemPrivHex },
          { trustedAdders: [node.keyringCap.iss] },
        )
        result[node.collectionId] = await encryptor.decrypt(sealed)
      } catch {
        // Revoked, cleared, or not yet written — omit it, keep the rest.
      }
    }),
  )
  return result
}

// ── Public tier ────────────────────────────────────────────────────────────────

/** One node of a space's public tier: its id, and the collection id it holds
 *  (which on the object index — and on `docPath` — is the node's `type`). */
export interface PublicSpaceMirrorNode {
  id: string
  type: string
}

export interface ReadPublicSpaceMirrorOptions {
  rendezvous: { baseUrl: string; namespace: string }
  spaceId: string
  /** The nodes to read, when the caller already knows them (from a share link,
   *  a deep link, its own records). When omitted, the world-readable public
   *  object directory is pulled instead and every entry it lists for
   *  `spaceId` is read. */
  nodes?: readonly PublicSpaceMirrorNode[]
  /** Which collections this reader recognizes, applied to whichever node list
   *  is in play. Default: accept all of them — an explicit `nodes` list is
   *  already the caller's own choice, and the directory only ever advertises
   *  nodes stored `access:"public"`. */
  isKnownCollection?: (type: string) => boolean
  /** Same widened template the writer and the other readers take. */
  docPath: (collectionId: string, spaceId: string, nodeId: string) => string
  /** Public-object-directory shard to enumerate. Ignored when `nodes` is
   *  given. Default `"public"`, matching `starfish-spaces`'
   *  `readObjectDirectory`. */
  directoryShard?: string
  fetch?: typeof fetch
}

/**
 * Read a space's PUBLIC tier — the collections `SpaceMirrorChannel` wrote with
 * `tier: "public"`, stored as plaintext at a world-readable path. No grant, no
 * cap, no keyring.
 *
 * It cannot enumerate the space the way `readSpaceMirror` does (the object
 * index is `space:member`), hence either `opts.nodes` or the world-readable
 * public object directory, which by construction lists only `access:"public"`
 * nodes.
 *
 * A node whose document carries `_encrypted` is OMITTED, never returned as a
 * sealed envelope the caller would treat as data. Omission rather than a throw
 * because a public -> private flip writes the encrypted content BEFORE
 * patching the stored access, so for that window the directory advertises a
 * node whose content is already sealed.
 */
export async function readPublicSpaceMirror(
  opts: ReadPublicSpaceMirrorOptions,
): Promise<Record<string, unknown>> {
  const client = makeAnonSpaceClient({
    baseUrl: opts.rendezvous.baseUrl,
    namespace: opts.rendezvous.namespace,
    fetch: opts.fetch ?? globalThis.fetch,
  })

  let candidates: readonly PublicSpaceMirrorNode[]
  if (opts.nodes) {
    candidates = opts.nodes
  } else {
    // Unlike `readObjectDirectory`, a failed directory pull is NOT swallowed
    // into an empty list: "server unreachable" must not look like "this space
    // publishes nothing".
    const dirDoc = await pullJson(client, objectDirectoryPath(opts.directoryShard ?? "public"))
    candidates = parseObjectDirectoryDoc(dirDoc)
      .filter((entry) => entry.spaceId === opts.spaceId)
      .map((entry) => ({ id: entry.id, type: entry.type }))
  }

  const isKnown = opts.isKnownCollection ?? (() => true)
  const mirrorNodes = candidates.filter((node) => isKnown(node.type))
  const result: Record<string, unknown> = {}
  if (mirrorNodes.length === 0) return result

  await Promise.all(
    mirrorNodes.map(async (node) => {
      const doc = await pullJson(client, opts.docPath(node.type, opts.spaceId, node.id))
      if (isSealed(doc)) return
      result[node.type] = doc ?? {}
    }),
  )
  return result
}
