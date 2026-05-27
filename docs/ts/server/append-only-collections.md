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
| `maxItems` | `number` | unset (unlimited) | Reject an append once the stored element count reaches this many — see [Bounding & scaling](#bounding--scaling-maxitems--chunksize). Requires `persist`. |
| `chunkSize` | `number` | unset (single document) | Store the log as fixed-size sealed chunks instead of one growing blob, bounding append cost — see [Bounding & scaling](#bounding--scaling-maxitems--chunksize). Requires `persist`. |
| `requireAuthorSignature` | `boolean` | `true` | Require a cryptographic [author proof](#author-proof-requireauthorsignature) on every append. Set `false` only for an unauthenticated/public-write log where author identity is meaningless. |

> The old `checkLastItem` option was **removed**. Appends are now always accepted content-wise (see below); there is no `baseHash` conflict check on an append.

## Behavior (persist=true)

On every push (after the normal authorization checks — caps, roles, expiry, rate/size limits):

1. The element payload (`body.data`) is read and sanitized.
2. The [author proof](#author-proof-requireauthorsignature) is verified (unless `requireAuthorSignature: false`).
3. The server resolves the element timestamp `ts` (see **Timestamps** below).
4. `{ ts, data, authorPubkey, authorSignature }` is appended as the last element of `data[field]`.
5. The document is written; the queue event is published (if a queue is configured).

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

### Author proof (`requireAuthorSignature`)

An append-only log is often multi-writer (many members, or a public write link), so the **author** of
each element must be verifiable — not a self-declared field a peer could spoof. By default
(`requireAuthorSignature: true`) every append carries a cryptographic author proof:

- **Client** — `client.append()` signs the element `data` with the same key that signs the HTTP
  request (the cap subject, or the redeemer of an audience link) and attaches
  `{ authorPubkey, authorSignature }` to the body. The signature is Ed25519 over
  `"starfish-append-author-v1\n" + stableStringify({ k: documentKey, d: data })` (see
  `signAppendAuthor` / `sign_append_author` in `starfish-protocol`). It is independent of
  `ts`/`baseHash`, and bound to the `documentKey` (the storage path = the push path minus `/push/`).
- **Server** — on each append it:
  1. requires `authorPubkey` + `authorSignature` (else `400`);
  2. requires `authorPubkey` to equal the **authenticated request presenter** — the cap-cert subject
     or audience redeemer key — so a writer cannot claim someone else's identity (else `403`);
  3. verifies the signature over the **sanitized** element (the exact bytes it stores) (else `403`).
  The proof is then stored on the element, so any reader who pulls the log re-verifies it with
  `verifyAppendAuthor` / `verify_append_author` — recompute the author's id from `authorPubkey`
  (e.g. `userIdFromPubHex`) and trust *that*, never a self-declared id inside `data`.

Because the author key is bound to the request presenter, the proof composes with the cap model: an
audience write-link allow-listed to specific keys yields elements provably authored by those keys.

Set `requireAuthorSignature: false` only for a log where author identity is meaningless (e.g. an open,
unauthenticated ingest endpoint). When off, the server still **stores** any proof the client sent (so
readers can opt into verifying) but does not require or check one.

> **Path binding:** the signature binds the author to the element `data` AND the `documentKey`, so a
> signed element cannot be replayed under a different document key (the signature no longer matches).
> Merge documents carry the same proof under a distinct domain tag (`starfish-doc-author-v1`).

### Incremental pull (checkpoint)

Each element carries its own `ts`. When a client sends `?checkpoint=<ts>`:

- Only elements with `ts` **strictly greater** than the checkpoint are returned in `data[field]`.
- Other top-level fields in the document are returned as-is.
- A full pull (no checkpoint) returns the complete array.

Because the array is strictly increasing in `ts`, the server locates the slice start with a binary search rather than scanning. This only trims what is **returned** — the whole document is still read and JSON-parsed first (O(N)). See [Size considerations](#size-considerations).

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

### Incremental cursor (`AppendLogCursor`)

For the common "pull only what's new" pattern, `AppendLogCursor` tracks the checkpoint for you. The checkpoint is **derived from the last element the cursor holds**, so it resumes correctly whether that element came from this session's pull or was persisted and rehydrated on a fresh page. The manual `since` calls above remain the escape hatch; `last`/windowing stays a raw `client.pull` concern (a cursor only ever moves forward).

```ts
import { AppendLogCursor } from "@drakkar.software/starfish-client"

// Cold start (nothing persisted) → first pull() fetches the whole collection
const log = new AppendLogCursor({ client, pullPath: "/pull/events" })
const all = await log.pull()

// Warm start: rehydrate from persisted data → first pull() resumes incrementally
const log2 = new AppendLogCursor({
  client,
  pullPath: "/pull/events",
  initialItems: await store.load(),  // raw {ts,data} envelopes; or pass { since: persistedCheckpoint }
})
const fresh = await log2.pull()      // only elements newer than the last held
await store.save(log2.getItems())    // persist the full log for next session

// Optional: decrypt each element's data + verify its author signature on read.
// Verification runs over the stored (pre-decryption) data and throws
// AppendAuthorError on any failure, leaving the cursor unchanged.
const secure = new AppendLogCursor({
  client,
  pullPath: "/pull/events",
  encryptor: createKeyringEncryptor(keyring, deviceKemKeys),
  verifyAuthor: true,
})
```

```python
from starfish_sdk import AppendLogCursor

# Cold start → first pull() fetches everything
log = AppendLogCursor(client, "/pull/events")
all_items = await log.pull()

# Warm start: resume from persisted data (or since=persisted_checkpoint)
log2 = AppendLogCursor(client, "/pull/events", initial_items=store.load())
fresh = await log2.pull()
store.save(log2.items)

# Optional: decrypt + verify author on read
secure = AppendLogCursor(
    client,
    "/pull/events",
    encryptor=create_keyring_encryptor(keyring, device_kem_keys),
    verify_author=True,
)
```

> `verifyAuthor` checks each signature is valid for the element's self-declared `authorPubkey`; it does **not** by itself restrict *which* authors are accepted. For a single-author log set `expectedAuthorPubkey`; for a multi-writer log, check each `authorPubkey` against your authorization source (keyring / member list) after pull. The signature binds `data` + the document key but **not** `ts`, so a malicious server can reorder/re-timestamp authentic elements without breaking verification — trust `ts` only as far as you trust the server.

#### Tolerating unreadable elements (`onElementError`)

By default a verify/decrypt failure is **atomic**: the pull throws and the checkpoint does not advance, so nothing that could never be re-fetched is silently skipped. For a **multi-writer / E2EE** log where the occasional element is legitimately unreadable (keyring skew, a foreign or wrong-key element), set `onElementError: "skip"` (`on_element_error="skip"` in Python): the bad element is dropped from the returned batch and **the checkpoint still advances past it**, so one poison element can't blank — or permanently wedge — the log. TS reports the dropped count via `logger.pullSuccess` (`SyncMetrics.skippedCount`).

> SECURITY: `"skip"` also silently drops **author-verification** failures, not just decryption failures. If you need strict authorship, keep `onElementError: "throw"` for the verification step, or set `verifyAuthor.expectedAuthorPubkey` / check each `authorPubkey` against your authorized set after pull.

#### Concurrency

`pull()` is **safe to call concurrently** — overlapping calls are serialized internally (a promise chain in TS, an `asyncio.Lock` in Python), so each runs against the checkpoint the previous one advanced and no two pulls fetch and double-append the same window. A failed pull does not wedge the queue. (You still get one network round-trip per call; coalesce upstream if you fire many triggers.)

#### E2EE-safe persistence (`persistEncrypted`)

The warm-start round-trip above persists `getItems()`. With an `encryptor` that defaults to storing **decrypted** data — so persisting it would write plaintext to disk. For an end-to-end-encrypted log, set `persistEncrypted: true` (`persist_encrypted=True`): the cursor keeps each element's **ciphertext**, so `getItems()` is safe to persist at rest, while `pull()` still returns the freshly-decrypted batch. Render warm-started history (the seeded ciphertext) with `getDecryptedItems()` (`get_decrypted_items()` in Python), which decrypts the full held log and honors the `onElementError` policy.

```ts
// E2EE stream: persist ciphertext, render decrypted, tolerate unreadable elements
const log = new AppendLogCursor({
  client,
  pullPath: "/pull/streamchat",
  encryptor: createKeyringEncryptor(keyring, deviceKemKeys),
  persistEncrypted: true,
  onElementError: "skip",
  initialItems: await store.load(),     // ciphertext persisted last session
})
const history = await log.getDecryptedItems()  // render seeded history (no network)
const fresh = await log.pull()                  // decrypted delta
await store.save(log.getItems())                // ciphertext back to disk
```

```python
log = AppendLogCursor(
    client,
    "/pull/streamchat",
    encryptor=create_keyring_encryptor(keyring, device_kem_keys),
    persist_encrypted=True,
    on_element_error="skip",
    initial_items=store.load(),          # ciphertext persisted last session
)
history = log.get_decrypted_items()      # render seeded history (no network)
fresh = await log.pull()                 # decrypted delta
store.save(log.items)                    # ciphertext back to disk
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

**Whole-document** author proof (`signDocAuthor`, the kind `SyncManager` attaches) does **not** apply to append-only collections: the stored value is a transformed wrapper (`{ items: [{ ts, data }, …] }`), not the raw client payload, so a document-level signature can't be verified against it.

**Per-element** author proof does apply. Each appended element can carry its own `authorPubkey` + `authorSignature` (`signAppendAuthor` over that element's `data`, bound to the document key); the server verifies it on append, and a reader can re-verify it — either directly via `verifyAppendAuthor` / `verify_append_author`, or automatically by passing `verifyAuthor` to [`AppendLogCursor`](#incremental-cursor-appendlogcursor).

## Size considerations

By default the whole feature keeps **every element in a single document**. That has real cost as a log grows:

- **Append is O(N) per call.** Each append reads the entire document, parses it, copies the array, re-serializes, and writes it back. The work is proportional to the current size, so **building a log of N elements one append at a time is O(N²)**.
- **Pull parses the whole document, O(N) — even with `?checkpoint=`.** The checkpoint trims what is *returned*, not what is *read*: the server still reads and JSON-parses the entire blob before the binary search. A checkpoint pull keeps the **response** small but not the server-side **parse**.

Three levers address this — combine as needed:

- **`chunkSize` (segmented storage)** — the library-level fix: bounds append to O(chunkSize) and lets `?checkpoint=`/`?last=` read only the chunks they need. See [Bounding & scaling](#bounding--scaling-maxitems--chunksize) below.
- **`maxItems` (cap)** — refuse to let a single document grow without bound; steers callers to partitioning.
- **Partition by a path parameter** — bounds N per document regardless of layout:
  ```ts
  // Partition by day: events/2024-01-15
  { storagePath: "events/{date}" }
  ```

These costs (and the `chunkSize` improvement) are characterized by opt-in stress suites (kept out of the default test run). Run them to see the timings on your hardware:

```bash
# TypeScript (from packages/ts/server)
STARFISH_STRESS=1 pnpm exec vitest run tests/router/append-only.stress.test.ts --reporter=verbose

# Python (from packages/python/server)
uv run pytest -s -m stress tests/protocol/test_append_stress.py
```

## Bounding & scaling (`maxItems` / `chunkSize`)

Two **opt-in** knobs address unbounded growth. Both are additive — a collection that sets neither keeps the single-document layout exactly — and both preserve the wire contract (pull response shape, `hash({ n, last })`, `?checkpoint=`/`?last=`), so clients and stored-vector conformance are unaffected. They are independent and may be combined.

### `maxItems` — cap

```ts
appendOnly: { type: "by_timestamp", maxItems: 50000 }
```

`maxItems: N` stores up to **N** elements; the **(N+1)th** append is rejected with **`409 { error: "append_limit_exceeded", limit }`** and nothing is written. The cap is configuration (not data), so the limit is echoed. Use it as a guardrail that pushes callers toward partitioning a high-volume stream by a path parameter (e.g. `storagePath: "events/{date}"`). It *prevents* the pathological single huge log; it does not make one fast — for that, use `chunkSize`.

### `chunkSize` — segmented storage

```ts
appendOnly: { type: "by_timestamp", chunkSize: 10000 }  // ~10000 recommended
```

Instead of one growing blob, the log is stored as fixed-size **sealed chunks** plus a small **head** document:

- **Head** at the document key (`events/2024-01-15`) — `{ n, ts, hash, chunkSize, tailKey, … }`, still a single object, so existence/TTL reads are unchanged.
- **Chunks** under a sibling prefix (`events/2024-01-15__seg/`), each holding up to `chunkSize` `{ts,data}` envelopes. **The chunk key is its first element's `ts`, zero-padded.** Because `ts` is strictly increasing, the lexicographically sorted key list (one `listKeys` call — *no chunk contents*) tells the server every chunk's time range.

Result:

- **Append is O(chunkSize)** — it touches only the head and the open tail chunk, so building a long log is no longer O(N²).
- **`?checkpoint=` reads only the chunks it needs** — the server locates the one boundary chunk (the last whose first-ts ≤ checkpoint) by a key-string comparison and reads it plus the chunks after it; every earlier chunk is skipped *without being read*. `?last=K` reads only the final `⌈K/chunkSize⌉+1` chunks. A full pull still reads everything (it returns everything) — keep using `?checkpoint=`/`?last=` for incremental sync.

**Lazy migration**: enabling `chunkSize` on a collection that already has a single-document log migrates it to chunks on the next append (a one-time O(N) append; bounded thereafter). **Stickiness**: once a document is segmented it stays segmented even if `chunkSize` is later removed from config — otherwise the next append would orphan the existing chunks.

**Batch-pull caveat**: the `/batch/pull` endpoint is not append/checkpoint-aware. For a **chunked** append-only collection it returns only the head's non-array `data` (no elements). Use the normal `/pull/...` endpoint (with `?checkpoint=`/`?last=`) for append-only data. (Batch pull *can* now address `{param}` collections — `{identity}` is auto-filled and other params come from its `params` query — but the checkpoint caveat above still applies to chunked append-only ones.)

## Migration

This format is **breaking** and not backward-compatible (3.0.0-alpha):

- Elements are now `{ ts, data }` objects (previously raw items with a parallel `timestamps` array). Existing append-only documents from an earlier alpha must be **wiped** — they are not auto-migrated.
- `appendOnly` is now `{ type: "by_timestamp", … }`; `appendOnly: true` and bare-object shorthands still normalize. `checkLastItem` is gone.
- From `queueOnly`: `queueOnly: true` → `appendOnly: { type: "by_timestamp", persist: false }`.
