/**
 * TTL / document expiration utilities.
 *
 * TTL is enforced on read (check-on-pull): when a document is pulled and its
 * timestamp + ttlMs < now, the server returns empty data. There is no background
 * cleanup — expired data remains in storage until overwritten by a new push.
 *
 * To implement background cleanup, the ObjectStore interface would need to
 * support key listing, which is not currently part of the interface.
 */

/** Check if a document has expired based on its last-modified timestamp and TTL. */
export function isExpired(timestamp: number, ttlMs: number): boolean {
  if (timestamp === 0) return false // Never written — not expired
  if (ttlMs <= 0) return false // Non-positive TTL means never expires
  return Date.now() - timestamp > ttlMs
}
