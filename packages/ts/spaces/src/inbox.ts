/**
 * Inbox client helpers — read the `inbox/{identity}/{shard}` collection.
 *
 * Reads require a cap that covers `inbox/{identity}/**`. The owner's
 * `accountScope` / `linkedDeviceScope` already grants it — use `session.accountClient`.
 */
import type { StarfishClient } from "@drakkar.software/starfish-client"
import type { Session } from "./session.js"

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
