/**
 * Inbox client helpers — read the `inbox/{identity}/{shard}` collection.
 *
 * Reads require a cap that covers `inbox/{identity}/**`. The owner's
 * `accountScope` / `linkedDeviceScope` already grants it — use `session.accountClient`.
 */
import type { StarfishClient } from "@drakkar.software/starfish-client"
import type { Session } from "./session.js"
import { makeAnonSpaceClient } from "./client.js"

/** Current UTC month shard in `YYYY-MM` format. */
export function inboxShard(): string {
  return new Date().toISOString().slice(0, 7)
}

/**
 * The current and previous UTC month shards — ensures an invite delivered near a
 * month boundary is still visible in the next month's scan.
 */
export function inboxShards(): string[] {
  const now = new Date()
  const y = now.getUTCFullYear()
  const m = now.getUTCMonth() // 0-indexed
  const current = `${y}-${String(m + 1).padStart(2, "0")}`
  const prevY = m === 0 ? y - 1 : y
  const prevM = m === 0 ? 12 : m
  const previous = `${prevY}-${String(prevM).padStart(2, "0")}`
  return [current, previous]
}

/** One inbox element as stored in the append-only shard. */
export interface InboxElement {
  ts: number
  data: Record<string, unknown>
}

/**
 * Append a pre-built element to `recipientUserId`'s inbox shard as an anonymous
 * public write, authored by the session identity.
 *
 * The inbox collection is `writeRoles:["public"]`, so no cap header is sent; the
 * Ed25519 author proof (the session's device keys) is bound to the document key and
 * surfaces the sender via `sealed.entry.addedBy` on the receive path. The caller is
 * responsible for sealing `element` first (see `resource-requests` for the canonical
 * seal-then-append pattern); use {@link inboxShard} for the current UTC shard.
 */
export async function appendToInbox(
  session: Session,
  recipientUserId: string,
  shard: string,
  element: Record<string, unknown>,
): Promise<void> {
  const anonClient = makeAnonSpaceClient({ baseUrl: session.baseUrl, namespace: session.namespace })
  await anonClient.appendAnonymous(
    session.layout.inboxPush(recipientUserId, shard),
    element,
    { edPubHex: session.keys.edPub, edPrivHex: session.keys.edPriv },
  )
}

/**
 * Pull one shard of `identity`'s inbox via `client`. Best-effort: returns `[]`
 * on any error (unreachable server, 403 stale cap, 404 empty month, etc.).
 */
export async function pullInbox(
  client: StarfishClient,
  identity: string,
  shard: string,
  session: Session,
): Promise<InboxElement[]> {
  return (await client
    .pull<InboxElement>(session.layout.inboxPull(identity, shard), {
      appendField: "items",
      full: true,
    })
    .catch(() => [])) as unknown as InboxElement[]
}
