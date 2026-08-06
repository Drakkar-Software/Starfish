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
 */
import { StarfishClient, type StarfishCapProvider } from "@drakkar.software/starfish-client"
import type { CapCert } from "@drakkar.software/starfish-protocol"
import { createKeyringEncryptor, type Keyring } from "@drakkar.software/starfish-keyring"

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
  /** Same bare-path template `SpaceMirrorChannel` was configured with. */
  docPath: (spaceId: string, nodeId: string) => string
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
  const keyringResult = await client.pull(`/pull/${spaceKeyringPath(opts.spaceId)}`)
  const keyringDoc = typeof keyringResult.data === "string" ? JSON.parse(keyringResult.data) : keyringResult.data
  if (!keyringDoc || typeof keyringDoc !== "object" || !(keyringDoc as { epochs?: unknown }).epochs) {
    throw new Error("readSpaceMirror: this space has no keyring yet — ask the owner to sync at least once")
  }
  const encryptor = await createKeyringEncryptor(
    keyringDoc as Keyring,
    { kemPubHex: opts.cap.subKem ?? "", kemPrivHex: opts.devKemPrivHex },
    { trustedAdders: [opts.cap.iss] },
  )

  // Independent, read-only pulls — one per node — so run them concurrently
  // rather than paying N sequential round trips on every live read/poll.
  await Promise.all(
    mirrorNodes.map(async (node) => {
      const docResult = await client.pull(`/pull/${opts.docPath(opts.spaceId, node.id)}`)
      const sealed = typeof docResult.data === "string" ? JSON.parse(docResult.data) : docResult.data
      if (!sealed || typeof sealed !== "object" || !("_encrypted" in sealed)) {
        result[node.type] = sealed ?? {}
        return
      }
      result[node.type] = await encryptor.decrypt(sealed as { _encrypted: string; _epoch?: number })
    }),
  )
  return result
}
