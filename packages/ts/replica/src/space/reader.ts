/**
 * Session-less read side of a space mirror: given a read-only member cap for
 * a space (minted via `starfish-spaces`' `inviteToSpace`), pull and decrypt
 * every node this reader recognizes. The known-collection predicate and the
 * document-path template are caller-supplied.
 *
 * Deliberately independent of `Session`/`SpacePort` (../space/port.ts) — a
 * grant holder is NOT a space member with a wallet, just someone holding a
 * cap-cert + an ephemeral keypair. This is the one place in `./space` that
 * builds its own `StarfishClient` rather than going through a `Session`.
 *
 * `readPublicSpaceMirror` at the bottom is the same idea taken one step
 * further: the PUBLIC tier needs no grant either, so it holds no cap and no
 * keyring at all and reads through an anonymous client.
 */
import { StarfishClient, type StarfishCapProvider } from "@drakkar.software/starfish-client"
import type { CapCert } from "@drakkar.software/starfish-protocol"
import { createKeyringEncryptor, type Keyring } from "@drakkar.software/starfish-keyring"
import { makeAnonSpaceClient, parseObjectDirectoryDoc } from "@drakkar.software/starfish-spaces"

/** What `createKeyringEncryptor` hands back — named here so the lazily
 *  memoized keyring promise below has a type without re-deriving it inline. */
type KeyringEncryptor = Awaited<ReturnType<typeof createKeyringEncryptor>>

/** A `StarfishCapProvider` that always returns the SAME cap + ephemeral
 *  private key — the entire point of a one-shot, session-less reader: no
 *  refresh, no rotation, just "prove possession of this one grant" on every
 *  request until the caller stops using it. */
class StaticCapProvider implements StarfishCapProvider {
  constructor(
    private readonly cap: CapCert,
    private readonly devEdPrivHex: string,
  ) {}
  async getCap(): Promise<{ cap: CapCert; devEdPrivHex: string }> {
    return { cap: this.cap, devEdPrivHex: this.devEdPrivHex }
  }
}

/** Storage path for a space's object index — hand-duplicated from
 *  `starfish-spaces`' `defaultSpaceLayout.objIndexPull`: a session-less
 *  reader has no `Session` (and therefore no `session.layout`) to resolve it
 *  through. */
function objectIndexPath(spaceId: string): string {
  return `spaces/${spaceId}/objects/_index`
}

/** Storage path for a space's ONE keyring doc — same reason as
 *  `objectIndexPath` above. */
function spaceKeyringPath(spaceId: string): string {
  return `spaces/${spaceId}/_keyring`
}

/** Storage path for one shard of the global public-object directory —
 *  hand-duplicated from `starfish-spaces`' `defaultSpaceLayout.objectDirPull`,
 *  same reason as the two paths above. */
function objectDirectoryPath(shard: string): string {
  return `_index/objects/${shard}`
}

/** Storage path for ONE node's own keyring (the isolated tier) — same reason
 *  as the paths above. */
function nodeKeyringPath(spaceId: string, nodeId: string): string {
  return `spaces/${spaceId}/objects/n/${nodeId}/_keyring`
}

interface ObjectIndexNode {
  id: string
  type: string
}

export interface ReadSpaceMirrorOptions {
  rendezvous: { baseUrl: string; namespace: string }
  spaceId: string
  cap: CapCert
  /** The grant holder's own ephemeral Ed25519 private key (hex) — the cap was
   *  minted for exactly this device's pubkey. */
  devEdPrivHex: string
  /** The grant holder's own ephemeral X25519 KEM private key (hex) —
   *  `inviteToSpace` added this device's KEM pubkey as a recipient of the
   *  space's ONE keyring; this is what lets this reader open that keyring
   *  itself (node content is sealed under it, not under the cap). */
  devKemPrivHex: string
  /** Which object-index nodes this reader recognizes as mirror content —
   *  everything else in the space's tree is ignored. */
  isKnownCollection: (type: string) => boolean
  /** Same bare-path template `SpaceMirrorChannel` was configured with —
   *  including its collection-id first argument, which here is the node's
   *  `type`, exactly as on the channel's clear path. Widened in lockstep so
   *  ONE function literal can be shared by the writer and this reader; a
   *  path template that keys on the collection id (a public collection at a
   *  stable shareable path, say) would otherwise be unreadable. */
  docPath: (collectionId: string, spaceId: string, nodeId: string) => string
  fetch?: typeof fetch
}

/**
 * Pull and decrypt every node in `opts.spaceId`'s object index that
 * `opts.isKnownCollection` recognizes. A REAL live read, not a point-in-time
 * export — call this again any time to see the latest write. Returns only
 * collections the space actually has a node for; one disabled since the
 * grant was minted simply won't appear (its node was cleared, not deleted —
 * see `SpaceMirrorChannel`'s clear-on-disable — so this reflects the CURRENT
 * state honestly, not a stale snapshot of what existed at grant time).
 */
export async function readSpaceMirror(
  opts: ReadSpaceMirrorOptions,
): Promise<Record<string, unknown>> {
  const client = new StarfishClient({
    baseUrl: opts.rendezvous.baseUrl,
    namespace: opts.rendezvous.namespace,
    fetch: opts.fetch ?? globalThis.fetch,
    capProvider: new StaticCapProvider(opts.cap, opts.devEdPrivHex),
  })

  const indexResult = await client.pull(`/pull/${objectIndexPath(opts.spaceId)}`)
  const indexDoc = typeof indexResult.data === "string" ? JSON.parse(indexResult.data) : indexResult.data
  const nodes: ObjectIndexNode[] = Array.isArray((indexDoc as { objects?: unknown })?.objects)
    ? (indexDoc as { objects: ObjectIndexNode[] }).objects
    : []
  const mirrorNodes = nodes.filter((node) => opts.isKnownCollection(node.type))
  const result: Record<string, unknown> = {}
  if (mirrorNodes.length === 0) return result

  // Node content is sealed under the space's ONE keyring, not under the cap
  // itself — open it once, reused for every node below. `cap.iss` is the
  // space owner's root edPub (who invited this device) — the only trusted
  // adder a session-less reader can name.
  //
  // LAZY, and deliberately so: a space whose every collection is written at
  // the PUBLIC tier (`SpaceMirrorChannel`'s `tier: "public"` — plaintext at a
  // world-readable path) never mints a keyring at all, because nothing in it
  // was ever encrypted. Pulling the keyring up front turned that space — one
  // this reader can read in full — into a hard throw on a doc that legitimately
  // does not exist. So the pull happens on the FIRST node whose pulled document
  // actually carries `_encrypted`, and not at all when none does.
  //
  // Memoized on the in-flight promise, not on the resolved value: the pulls
  // below run concurrently under `Promise.all`, so two encrypted nodes would
  // otherwise both find "no encryptor yet" and race into two keyring pulls.
  let keyringPull: Promise<KeyringEncryptor> | null = null
  function openKeyring(): Promise<KeyringEncryptor> {
    keyringPull ??= (async () => {
      const keyringResult = await client.pull(`/pull/${spaceKeyringPath(opts.spaceId)}`)
      const keyringDoc = typeof keyringResult.data === "string" ? JSON.parse(keyringResult.data) : keyringResult.data
      if (!keyringDoc || typeof keyringDoc !== "object" || !(keyringDoc as { epochs?: unknown }).epochs) {
        throw new Error("readSpaceMirror: this space has no keyring yet — ask the owner to sync at least once")
      }
      return createKeyringEncryptor(
        keyringDoc as Keyring,
        { kemPubHex: opts.cap.subKem ?? "", kemPrivHex: opts.devKemPrivHex },
        { trustedAdders: [opts.cap.iss] },
      )
    })()
    return keyringPull
  }

  // Independent, read-only pulls — one per node — so run them concurrently
  // rather than paying N sequential round trips on every live read/poll.
  await Promise.all(
    mirrorNodes.map(async (node) => {
      const docResult = await client.pull(`/pull/${opts.docPath(node.type, opts.spaceId, node.id)}`)
      const sealed = typeof docResult.data === "string" ? JSON.parse(docResult.data) : docResult.data
      if (!sealed || typeof sealed !== "object" || !("_encrypted" in sealed)) {
        result[node.type] = sealed ?? {}
        return
      }
      const encryptor = await openKeyring()
      result[node.type] = await encryptor.decrypt(sealed as { _encrypted: string; _epoch?: number })
    }),
  )
  return result
}

// ── Isolated tier ──────────────────────────────────────────────────────────────

/** One isolated node a grant covers. The caps are the two `inviteToNode(...,
 *  {isolated: true})` mints: `contentCap` (`objinv`) fetches the document,
 *  `keyringCap` (`nodekeyring`) fetches the key to open it. */
export interface IsolatedMirrorNodeGrant {
  /** The node's `type` in the object index — the collection id. Supplied by
   *  the grant rather than read from `objindex`, which is `space:member` and
   *  therefore unreadable to a per-node grant holder. */
  collectionId: string
  nodeId: string
  contentCap: CapCert
  keyringCap: CapCert
}

export interface ReadIsolatedSpaceMirrorOptions {
  rendezvous: { baseUrl: string; namespace: string }
  spaceId: string
  /** Exactly the nodes this grant covers — no enumeration step, because a
   *  per-node grant holder is not on the space roster and cannot list. */
  nodes: readonly IsolatedMirrorNodeGrant[]
  /** The grant holder's own ephemeral Ed25519 private key (hex); every cap was
   *  minted for this device's pubkey. */
  devEdPrivHex: string
  /** The grant holder's own ephemeral X25519 KEM private key (hex) — added as
   *  a recipient of each node's OWN keyring at invite time. */
  devKemPrivHex: string
  /** Same bare-path template the writer was configured with. */
  docPath: (collectionId: string, spaceId: string, nodeId: string) => string
  fetch?: typeof fetch
}

/**
 * Session-less read side of the ISOLATED tier: pull and decrypt each node the
 * grant names, every one through its own keyring.
 *
 * Differs from `readSpaceMirror` in the two ways the tier implies. There is no
 * object-index pull — `objindex` is `space:member`, and the whole point of an
 * isolated grant is that its holder never joins the roster — so the node list
 * comes from the grant. And there is no one shared keyring: each node carries
 * its own, so revoking one node leaves the others readable.
 *
 * A node whose content or keyring pull fails is OMITTED rather than failing
 * the batch: with per-node grants, one revoked node is a normal state, not an
 * error for the rest.
 */
export async function readIsolatedSpaceMirror(
  opts: ReadIsolatedSpaceMirrorOptions,
): Promise<Record<string, unknown>> {
  const clientFor = (cap: CapCert) =>
    new StarfishClient({
      baseUrl: opts.rendezvous.baseUrl,
      namespace: opts.rendezvous.namespace,
      fetch: opts.fetch ?? globalThis.fetch,
      capProvider: new StaticCapProvider(cap, opts.devEdPrivHex),
    })

  const result: Record<string, unknown> = {}
  await Promise.all(
    opts.nodes.map(async (node) => {
      try {
        const docResult = await clientFor(node.contentCap).pull(
          `/pull/${opts.docPath(node.collectionId, opts.spaceId, node.nodeId)}`,
        )
        const sealed = typeof docResult.data === "string" ? JSON.parse(docResult.data) : docResult.data
        if (!sealed || typeof sealed !== "object") return
        if (!("_encrypted" in sealed)) {
          result[node.collectionId] = sealed
          return
        }
        const keyringResult = await clientFor(node.keyringCap).pull(
          `/pull/${nodeKeyringPath(opts.spaceId, node.nodeId)}`,
        )
        const keyringDoc =
          typeof keyringResult.data === "string" ? JSON.parse(keyringResult.data) : keyringResult.data
        if (!keyringDoc || typeof keyringDoc !== "object" || !(keyringDoc as { epochs?: unknown }).epochs) return
        const encryptor = await createKeyringEncryptor(
          keyringDoc as Keyring,
          { kemPubHex: node.keyringCap.subKem ?? "", kemPrivHex: opts.devKemPrivHex },
          { trustedAdders: [node.keyringCap.iss] },
        )
        result[node.collectionId] = await encryptor.decrypt(sealed as { _encrypted: string; _epoch?: number })
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
  /** Same widened template the writer (`SpaceMirrorChannel.docPath`) and
   *  `readSpaceMirror` take, so ONE function literal serves all three. The
   *  collection id comes first precisely so a public collection can live at a
   *  stable, shareable path — which is what makes it reachable from here. */
  docPath: (collectionId: string, spaceId: string, nodeId: string) => string
  /** Public-object-directory shard to enumerate. Ignored when `nodes` is
   *  given. Default `"public"`, matching `starfish-spaces`'
   *  `readObjectDirectory`. */
  directoryShard?: string
  fetch?: typeof fetch
}

/**
 * Read a space's PUBLIC tier — the collections `SpaceMirrorChannel` wrote with
 * `tier: "public"`, stored as plaintext at a world-readable path.
 *
 * No grant, no cap, no keyring: the client is `makeAnonSpaceClient`, exactly as
 * `readObjectDirectory` builds its own. That is the whole point of the public
 * tier — anyone holding the space id can read what its owner chose to publish,
 * with no invite in between.
 *
 * It cannot enumerate the space the way `readSpaceMirror` does: the object
 * index is `space:member`, so an anonymous caller may not list a space's nodes.
 * Hence either `opts.nodes` (ids the caller already has) or the world-readable
 * public object directory, which the server projects from `objindex` writes and
 * which by construction lists only `access:"public"` nodes.
 *
 * Keyed exactly like `readSpaceMirror`: collection id (the node `type`) ->
 * plaintext document.
 *
 * A node whose document comes back carrying `_encrypted` is OMITTED, never
 * returned: handing back the sealed envelope would give a caller ciphertext it
 * would go on to treat as data. Omission rather than a throw because that state
 * is reachable without anything being broken — `SpaceMirrorChannel` finishes a
 * public -> private flip by writing the encrypted content BEFORE patching the
 * node's stored access, so for that window the directory still advertises a
 * node whose content is already sealed. One such node must not cost every other
 * published collection its read.
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
    // into an empty list here: this is the sibling of `readSpaceMirror`, whose
    // own index pull throws, and "the server is unreachable" must not be
    // indistinguishable from "this space publishes nothing".
    const dirResult = await client.pull(`/pull/${objectDirectoryPath(opts.directoryShard ?? "public")}`)
    const dirDoc = typeof dirResult.data === "string" ? JSON.parse(dirResult.data) : dirResult.data
    candidates = parseObjectDirectoryDoc(dirDoc)
      .filter((entry) => entry.spaceId === opts.spaceId)
      .map((entry) => ({ id: entry.id, type: entry.type }))
  }

  const isKnown = opts.isKnownCollection ?? (() => true)
  const mirrorNodes = candidates.filter((node) => isKnown(node.type))
  const result: Record<string, unknown> = {}
  if (mirrorNodes.length === 0) return result

  // Same reasoning as `readSpaceMirror`: independent read-only pulls, run
  // concurrently rather than N sequential round trips.
  await Promise.all(
    mirrorNodes.map(async (node) => {
      const docResult = await client.pull(`/pull/${opts.docPath(node.type, opts.spaceId, node.id)}`)
      const doc = typeof docResult.data === "string" ? JSON.parse(docResult.data) : docResult.data
      if (doc && typeof doc === "object" && "_encrypted" in doc) return
      result[node.type] = doc ?? {}
    }),
  )
  return result
}
