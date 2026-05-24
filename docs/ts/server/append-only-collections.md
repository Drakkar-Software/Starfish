# Append-Only Collections

Append-only collections let clients push data without conflict detection. Every authorized push appends the incoming `data` to a stored array as a `{ ts, data }` element, or (with `persist: false`) skips storage entirely and just publishes to the configured queue.

They are the building block for **incremental sync**: `?checkpoint=<ts>` returns only the elements appended after a timestamp. (Regular, non-append collections always return the full document — checkpoint sync is an append-only feature.)

## When to use

- **Log / event / audit streams** — chat messages, activity feeds, audit trails, telemetry
- **Machine ingest** — a service or device appending events behind a write-scoped credential
- **Event publishing pipelines** — when you only need the queue consumer and never pull data back (`persist: false`)

## Configuration

```ts
// TypeScript server
{
  name: "events",
  storagePath: "events",                 // no path param needed for simple append
  readRoles: ["admin"],
  writeRoles: ["user"],
  encryption: "none",                    // "none" or "delegated" — both supported
  maxBodyBytes: 65536,
  appendOnly: { type: "by_timestamp" },  // defaults: field="items", persist=true
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
    append_only=AppendOnlyConfig(type="by_timestamp"),  # field="items", persist=True
)
```

Shorthand: `appendOnly: true` (JSON / YAML) maps to `{ "type": "by_timestamp" }` (all defaults).

## AppendOnlyConfig options

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | `"by_timestamp"` | — (required) | Append strategy. Only `"by_timestamp"` is supported today; the field is a discriminator so other strategies can be added later. |
| `field` | `string` | `"items"` | Array field name in the stored document |
| `persist` | `boolean` | `true` | `false` = skip storage, publish queue only (replaces `queueOnly`) |

> The old `checkLastItem` option was **removed**. Appends are now always accepted content-wise (see below); there is no `baseHash` conflict check on an append.

## Behavior (persist=true)

On every push (after the normal authorization checks — caps, roles, expiry, rate/size limits):

1. The element payload (`body.data`) is read and sanitized.
2. The server resolves the element timestamp `ts` (see **Timestamps** below).
3. `{ ts, data }` is appended as the last element of `data[field]`.
4. The document is written; the queue event is published (if a queue is configured).

There is **no hash / conflict check** — an authorized append always succeeds (content-wise). Any `baseHash` a client sends is ignored. Concurrent appends to the same document are serialized by a per-key write lock, so no element is ever lost; they land in arrival order.

### Timestamps (server-assigned or client-supplied)

Let `latest` = the `ts` of the most recent stored element (or `-1` if the array is empty).

- **No `ts` in the request** → the server stores `max(now, latest + 1)`. The `max(..)` (rather than bare `now`) guarantees the array stays **strictly increasing** in `ts` even after a client previously stored a future timestamp — which keeps the checkpoint binary search correct.
- **`ts` supplied in the request body** (a non-negative integer, ms) → it must be **strictly greater** than `latest`. If so, the element is stored with that exact `ts`. Otherwise the server responds `409 { error: "non_monotonic_timestamp", latest }`.

A client-supplied `ts` lets you preserve an event's original time (e.g. backfilling, or a device that timestamps locally) while still guaranteeing a monotonic, checkpoint-friendly log.

### Hash semantics

The stored `hash` and pull-response `hash` is:

```
hash({ n: items.length, last: lastItem })
```

where `lastItem` is the element's **`data`** payload (not the `{ ts, data }` envelope). This is O(1) — independent of array size — and is used for ETag/304 short-circuiting. The `n` (length) component ensures two identical back-to-back pushes produce different hashes, preventing false 304 responses.

### Incremental pull (checkpoint)

Each element carries its own `ts`. When a client sends `?checkpoint=<ts>`:

- Only elements with `ts` **strictly greater** than the checkpoint are returned in `data[field]`.
- Other top-level fields in the document are returned as-is.
- A full pull (no checkpoint) returns the complete array.

Because the array is strictly increasing in `ts`, the server locates the slice start with a binary search (O(log N)) rather than scanning.

### Last-K pull

`?last=K` returns the K most recent elements. Applied after the checkpoint filter, so the two compose:

```
?last=50                  → last 50 elements of the full array
?checkpoint=<ts>&last=10  → elements since ts, then the last 10 of those
```

Store the largest `ts` you've seen and pass it as `since` on the next pull to receive only new elements.

### Stored document shape

```jsonc
{
  "v":    1,
  "data": { "items": [
    { "ts": 1714000001, "data": { "msg": "a" } },
    { "ts": 1714000023, "data": { "msg": "b" } },
    { "ts": 1714000099, "data": { "msg": "c" } }
  ] },
  "ts":   1714000099,                       // doc write-time = ts of the most recent element
  "hash": "hash({ n: 3, last: { msg: 'c' } })"
}
```

The document carries a single `ts` (its write-time, used for TTL and as the pull high-water mark). The old per-field `timestamps` tree no longer exists — each element's timestamp lives inside its own `{ ts, data }` envelope.

## Behavior (persist=false)

Replaces the old `queueOnly: true` flag:

- The server resolves `ts` (client-supplied or `now`), computes `hash(body.data)`, and publishes a queue event.
- Nothing is written to storage.
- Pull always returns `{ data: {}, hash: "" }`.

## Encryption modes

Append-only supports both `"none"` and `"delegated"`.

- **`none`** — `data` is stored as plaintext.
- **`delegated`** — the **client** encrypts each element's `data` before pushing; the server stores the resulting ciphertext blob inside the `{ ts, data }` envelope. The server never reads `data` — it only ever appends and reads the plaintext `ts`, so checkpoint filtering works unchanged. Encrypt/decrypt with the per-collection keyring encryptor (`createKeyringEncryptor` / `create_keyring_encryptor`), which already carries the keyring epoch (key version) and is AEAD-bound:

```ts
import { createKeyringEncryptor } from "@drakkar.software/starfish-keyring"

const enc = createKeyringEncryptor(keyring, deviceKemKeys)
// push: encrypt the element payload
await client.append("/push/events", await enc.encrypt({ msg: "secret" }))
// pull: decrypt each element's data
const els = await client.pull("/pull/events", { appendField: "items", since })
const plain = await Promise.all(els.map((e) => enc.decrypt(e.data)))
```

## Client usage

Append push and pull are built into `StarfishClient` — no separate import needed. Use `append()` for writes (no conflict check; optional client `ts`); the append `pull` returns the `{ ts, data }` envelopes.

```ts
import { StarfishClient } from "@drakkar.software/starfish-client"

// Append an element (server assigns ts)
await client.append("/push/events", { type: "click" })

// Append with a client-supplied timestamp (must be > the latest stored ts)
await client.append("/push/events", { type: "click" }, { ts: Date.now() })

// Pull the stored array → { ts, data }[]
const events = await client.pull("/pull/events", { appendField: "items" })

// Incremental pull — only elements since last sync
const newEvents = await client.pull("/pull/events", { appendField: "items", since: lastSyncTs })

// Last 50 elements
const recent = await client.pull("/pull/events", { appendField: "items", last: 50 })
```

```python
# Append an element (server assigns ts)
await client.append("/push/events", {"type": "click"})

# Append with a client-supplied timestamp
await client.append("/push/events", {"type": "click"}, ts=1714000000)

# Pull the stored array → list of {"ts", "data"}
events = await client.pull("/pull/events", append_field="items")

# Incremental pull
new_events = await client.pull("/pull/events", since=last_sync_ts)
```

## Compatibility matrix

| Combination | Supported |
|---|---|
| `encryption: "none"` | Yes |
| `encryption: "delegated"` | **Yes** (client encrypts each element; server stores it opaquely) |
| `objectSchema` | Yes (validates each element's `data` before appending) |
| `queue` | Yes |
| `ttlMs` | Yes (whole-document TTL, against the doc `ts`) |
| `fieldPermissions` | Yes |
| Binary collections (`allowedMimeTypes` without JSON) | No |
| `pullOnly` | No |
| `bundle` (persist=true) | No |
| `remote` replication | No |

## Author signatures

Author signature verification is **skipped** for append-only collections. Stored data is a transformed wrapper (`{ items: [{ ts, data }, …] }`), not the raw client payload, so signatures cannot be meaningfully verified against it.

## Size considerations

There is no built-in cap on array length. Push and full pull are O(N) in storage I/O — the full document is read on every push and returned on a full pull. Use checkpoint pulls to keep payloads proportional to new elements rather than total history. For high-volume streams, partition by path parameter to keep individual documents small:

```ts
// Partition by day: events/2024-01-15
{ storagePath: "events/{date}" }
```

## Migration

This format is **breaking** and not backward-compatible (3.0.0-alpha):

- Elements are now `{ ts, data }` objects (previously raw items with a parallel `timestamps` array). Existing append-only documents from an earlier alpha must be **wiped** — they are not auto-migrated.
- `appendOnly` is now `{ type: "by_timestamp", … }`; `appendOnly: true` and bare-object shorthands still normalize. `checkLastItem` is gone.
- From `queueOnly`: `queueOnly: true` → `appendOnly: { type: "by_timestamp", persist: false }`.
