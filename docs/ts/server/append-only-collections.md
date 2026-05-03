# Append-Only Collections

Append-only collections allow clients to push data without conflict detection. Every push appends the incoming `data` object to a stored array, or (with `persist: false`) skips storage entirely and just publishes to the configured queue.

## When to use

- **Log / event / audit streams** — chat messages, activity feeds, audit trails, telemetry
- **Event publishing pipelines** — when you only need the queue consumer and never need to pull data back (`persist: false`)

## Configuration

```ts
// TypeScript server
{
  name: "events",
  storagePath: "events",           // no path param needed for simple append
  readRoles: ["admin"],
  writeRoles: ["user"],
  encryption: "none",
  maxBodyBytes: 65536,
  appendOnly: {},                  // defaults: field="items", persist=true
}
```

```python
# Python server
CollectionConfig(
    name="events",
    storage_path="events",
    read_roles=["admin"],
    write_roles=["user"],
    encryption="none",
    max_body_bytes=65536,
    append_only=AppendOnlyConfig(),  # defaults: field="items", persist=True
)
```

Shorthand: `appendOnly: true` (JSON / YAML) maps to `{}` (all defaults).

## AppendOnlyConfig options

| Field | Type | Default | Description |
|---|---|---|---|
| `field` | `string` | `"items"` | Array field name in the stored document |
| `persist` | `boolean` | `true` | `false` = skip storage, publish queue only (replaces `queueOnly`) |
| `checkLastItem` | `boolean` | `false` | Validate `baseHash` against `hash(lastItem)` before appending |

## Behavior (persist=true)

On every push:
1. Server reads existing document
2. Appends `body.data` as last element of `data[field]`
3. Writes the updated document with per-item timestamps (one timestamp per item in the array)
4. Publishes queue event (if `queue` configured)

`baseHash` from the client is **ignored** unless `checkLastItem: true`.

**Concurrent appends:** The server retries the read-then-write loop up to 3 times on hash races. If all retries fail, returns `500 { error: "append_retry_exhausted" }`.

### Hash semantics

For `appendOnly persist=true` collections, the stored `hash` and pull-response `hash` is:

```
hash({ n: items.length, last: lastItem })
```

This is O(1) — independent of array size. It is used for ETag/304 short-circuiting and for `checkLastItem` conflict detection. The `n` (length) component ensures that two identical back-to-back pushes produce different hashes, preventing false 304 responses.

### Incremental pull (checkpoint)

Each item in the stored array has its own timestamp. When a client sends `?checkpoint=<ts>`:

- Only items appended **after** `ts` are returned in `data[field]`.
- Other fields in the document are returned as-is.
- A full pull (no checkpoint) returns the complete array.

The per-item timestamps array is monotonically non-decreasing, so the server locates the slice start with a binary search (O(log N)) rather than scanning the full array.

### Last-K pull

`?last=K` returns the K most recent items. Applied after the checkpoint filter, so the two compose:

```
?last=50              → last 50 items of the full array
?checkpoint=<ts>&last=10  → items since ts, then the last 10 of those
```

Useful for "latest N log lines" or a live feed tail without maintaining a client-side checkpoint.

```ts
// Full pull
const allEvents = await pullAppendList(client, "/pull/events")

// Incremental pull — only items since last sync
const newEvents = await pullAppendList(client, "/pull/events", { since: lastSyncTimestamp })

// Custom field name + incremental
const logs = await pullAppendList(client, "/pull/audit", { field: "logs", since: lastSyncTimestamp })
```

Store the `since` value (e.g. `Date.now()` after each pull) and pass it on the next pull to receive only new items.

### Stored document shape

```jsonc
{
  "data":       { "items": [ { ... }, { ... }, { ... } ] },
  "hash":       "hash({ n: 3, last: {...} })",
  "timestamps": { "items": [ 1714000001, 1714000023, 1714000099 ] }
}
```

The `timestamps[field]` array is parallel to `data[field]` — index `i` is the time item `i` was appended.

### Push performance

| Step | Cost |
|---|---|
| Storage read | O(N) — full document read |
| Hash computation | **O(1)** — `hash({ n, last })` only |
| Timestamps | **O(1)** — append to existing array |
| Storage write | O(N) — full document write |

CPU cost per push is O(1) regardless of array size.

## Behavior (persist=false)

Replaces the old `queueOnly: true` flag:
- Server computes `hash(body.data)` and publishes a queue event
- Nothing is written to storage
- Pull always returns `{ data: {}, hash: "" }`

## checkLastItem mode

With `checkLastItem: true`, the server validates the client's `baseHash` against the stored document hash before appending. The stored hash is `hash({ n: items.length, last: lastItem })`. Returns `409 { error: "hash_mismatch" }` if the array has changed since the client last read it.

- Empty store: client must send `""` or `null` as `baseHash`

**Concurrent-write detection:** The hash check runs inside the retry loop, using the same document read that feeds the write. If a concurrent write arrives between your read and your write, the retry re-reads the updated document and re-validates — so the second writer always gets `409` rather than silently appending. This is safe at the cost of one extra round-trip for the loser, not for the winner.

The simplest way to get the correct `baseHash` is to use the `hash` field from a pull response:

```ts
// Client pulls, uses response hash as baseHash for conditional append
const result = await client.pull("/pull/events")
const baseHash = result.hash  // use this directly
await client.push("/push/events", { msg: "new" }, baseHash)
```

## Client usage

Append-only push and pull are built directly into `StarfishClient` — no separate import needed.

```ts
import { StarfishClient } from "@drakkar.software/starfish-client"

// Append an item (baseHash=null — no conflict check)
await client.push("/push/events", { type: "click", ts: Date.now() }, null)

// Pull the full stored array → T[]
const events = await client.pull("/pull/events", { appendField: "items" })

// Incremental pull — only items since last sync
const newEvents = await client.pull("/pull/events", { appendField: "items", since: lastSyncTimestamp })

// Last 50 items (no checkpoint needed)
const recent = await client.pull("/pull/events", { appendField: "items", last: 50 })

// Custom field name + combine options
const newLogs = await client.pull("/pull/audit", { appendField: "logs", since: lastSyncTimestamp, last: 10 })
```

```python
# Append an item (base_hash=None — no conflict check)
await client.push("/push/events", {"type": "click", "ts": 1714000000}, None)

# Pull the full stored array → list
events = await client.pull("/pull/events", append_field="items")

# Incremental pull
new_events = await client.pull("/pull/events", since=last_sync_timestamp)

# Last 50 items, custom field
logs = await client.pull("/pull/audit", append_field="logs", last=50)
```

## Compatibility matrix

| Combination | Supported |
|---|---|
| Binary collections (`allowedMimeTypes` without JSON) | No |
| `pullOnly` | No |
| `remote` replication | No |
| `clientEncrypted` (persist=true) | No |
| `encryption: "delegated"` or `"group"` (persist=true) | No |
| `bundle` (persist=true) | No |
| `objectSchema` | Yes (validates each item's `data` before appending) |
| `queue` | Yes |
| `ttlMs` | Yes (whole document TTL) |
| `fieldPermissions` | Yes |

## Author signatures

Author signature verification is **skipped** for append-only collections. Stored data is a transformed wrapper (`{ items: [...] }`), not the raw client payload, so signatures cannot be meaningfully verified against it.

## Size considerations

There is no built-in cap on array length. Push and pull (without checkpoint) are O(N) in storage I/O — the full document is read on every push and returned on full pull. Use checkpoint pulls to keep payload size proportional to new items rather than total history.

For very high-volume streams (>10 K items per document), partition by path parameter to keep individual documents small:

```ts
// Partition by day: events/2024-01-15
{ storagePath: "events/{date}" }
```

This keeps each document bounded, and checkpoint pull handles incremental sync within each partition.

## Migration from queueOnly

| Old (≤ 1.x) | New (2.0+) |
|---|---|
| `queueOnly: true` | `appendOnly: { persist: false }` |
| `queue_only=True` (Python) | `append_only=AppendOnlyConfig(persist=False)` |

The wire protocol and queue event format are unchanged — only the config field name changes.
