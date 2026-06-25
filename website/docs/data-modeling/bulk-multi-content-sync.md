---
sidebar_position: 7
---

# Bulk & Multi-Content Sync

How to move many documents in as few round-trips as possible — reading many at once,
the patterns for writing many, keeping them fresh, and why the choices behind the
current design were made.

## Which tool do you need?

| Goal | Tool |
|------|------|
| Read several collections / documents in one request | [`batchPull`](#reading-many-at-once) |
| Read a server-defined set of related collections together | [Bundle pull](#bundle-pull) |
| Read one collection's document + its keyring together | [`withKeyring: true`](#withkeyring) |
| Read a maintained list (many items, one pull) | [Projection extension](#projection--one-list-one-pull) |
| Enumerate all docs under a key prefix, then pull them | [List endpoint + `batchPull`](#list-then-batch-pull) |
| Write several documents | [Fan-out push](#writing-many-at-once) |
| Stream real-time change notifications | [SSE + invalidate](#keeping-many-documents-fresh) |
| Read stale-then-refresh a document cheaply | [`staleWhileRevalidate`](#staleness-and-background-revalidation) |

---

## Reading many at once

### `batchPull` / `batchPullMany`

`StarfishClient.batchPull` issues a single `GET /batch/pull` and returns many
documents in one response. It can pull across **multiple collections** and **multiple
documents per collection** in a single request:

```ts
import { StarfishClient } from "@drakkar.software/starfish-client"

const client = new StarfishClient({ baseUrl: "https://api.example.com" })

// One call — three collections, two docs from "profile"
const result = await client.batchPull(
  ["profile", "settings", "theme"],
  {
    params: {
      profile: [
        { identity: "user-1" },
        { identity: "user-2" },
      ],
      // settings + theme: server auto-fills {identity} from the caller
    },
  },
)

// result.collections["profile"]  → [entry for user-1, entry for user-2]
// result.collections["settings"] → [entry for the caller]
// result.collections["theme"]    → [entry for the caller]
```

Each entry is `{ data, hash, timestamp }` on success or `{ error: string }` on
failure — a per-document error never fails the whole batch:

```ts
for (const entry of result.collections["profile"]) {
  if (entry.error) {
    console.warn("profile read failed:", entry.error)
    continue
  }
  console.log("profile data:", entry.data, "at", entry.timestamp)
}
```

For the common "many docs of one collection" case, `batchPullMany` is more ergonomic:

```ts
const entries = await client.batchPullMany("profile", [
  { identity: "user-1" },
  { identity: "user-2" },
  { identity: "user-3" },
])
// entries[0] → user-1, entries[1] → user-2, entries[2] → user-3
// Order matches paramsList. Entry is { data, hash, timestamp } or { error }.
```

**Append-aware batch pulls:**

Pass `appendParams` (index-aligned to each collection's `params` array) to get
bounded-tail reads for append-only collections in the same request:

```ts
const result = await client.batchPull({
  collections: ['events'],
  params: { events: [{ roomId: 'room-1' }, { roomId: 'room-2' }] },
  appendParams: { events: [{ since: lastSeen, last: 50 }, { last: 10 }] },
})
// result.collections.events[0].data.items — up to 50 new events for room-1
// result.collections.events[1].data.items — 10 newest events for room-2
```

`full:true` is disallowed in `appendParams` (DoS guard). Use `batchPullManyAppend`
for the common many-docs-of-one-collection case.

**Cross-space batch pulls:**

Reading the same collection across many spaces no longer requires N separate requests.
Sign the batch with the account-scoped client (whose cap covers `spaces/**`) and the
server's per-entry role enricher (`createSpacesRoleEnricher`, which defaults to
`allowTofu: false`) authorizes each entry against its own `_access` doc — entries
the caller is not a member of come back as `{ error: "Forbidden" }`:

```ts
import { readSpaceAccessBatch } from '@drakkar.software/starfish-spaces'

// Returns Map<spaceId, SpaceEntry> — only spaces the caller can read
const spaces = await readSpaceAccessBatch(session, ['sp-1', 'sp-2', 'sp-3'])
```

**Caveats:**

- **`full` disallowed in appendParams.** Use the normal `/pull/` endpoint for a full
  unbounded append-only read.
- **Server cap: 100 by default.** The server enforces `maxCollectionsPerBatch`
  (default **100**), counting both distinct collection names and the total number of
  individual document reads across all param-sets. An over-limit request gets a 4xx
  error before any reads are attempted.
- **`batchKeyDenySuffixes`** — the server blocks certain key suffixes from appearing in
  a cross-space batch by default (`_keyring` and `_members` are excluded). These
  sensitive sibling collections must be fetched via their own dedicated `/pull/` calls;
  requesting them through the batch endpoint returns `400 batch_key_denied`.
- **Errored and forbidden entries are indistinguishable in the Map.** `readSpaceAccessBatch`
  (and the underlying `/batch/pull` contract) silently omits spaces whose entry resolves
  to an error — whether that is `Forbidden` (not a member), a missing `_access` doc, or
  a transient server error. This matches the bundle-pull contract: callers cannot
  distinguish "not a member" from "server error" from the Map result alone.
- For a server-maintained roster of all spaces a user belongs to, a projection collection
  can be more efficient than per-entry batch fan-out: one pull returns the full membership
  list without enumerating individual space IDs on the client.

**Python:**

```python
result = await client.batch_pull(
    ["profile", "settings"],
    params={
        "profile": [{"identity": "user-1"}, {"identity": "user-2"}],
    },
)
entries = await client.batch_pull_many("profile", [{"identity": "user-1"}])
```

### Bundle pull

A *bundle* is a server-side configuration that groups multiple collections under one
base key. A single `GET /pull/{path}` returns all bundle members together:

```
GET /pull/spaces/sp-123
→ {
    "collections": {
      "metadata": { "data": {...}, "hash": "abc" },
      "members":   { "data": {...}, "hash": "def" }
    },
    "timestamp": 1716000000000
  }
```

Bundle pull is **server-defined** (the server config determines which collections are
grouped). The client has no say in which collections are included. Members for which
the caller lacks read access are silently omitted from the response — the call still
succeeds.

Contrast with `batchPull`:

| | `batchPull` | Bundle pull |
|---|---|---|
| What to pull | client-chosen at runtime | server-fixed at config time |
| Denied members | per-entry `{ error }` | silently absent |
| Path params | per-document, per-collection | shared (from the URL) |
| Auth scope | each collection's own `readRoles` | each member's own `readRoles` |

### `withKeyring`

When a collection uses delegated encryption, its sibling `_keyring` document must be
fetched alongside the main document to decrypt it. Passing `withKeyring: true` folds
both into a single request:

```ts
const result = await client.pull("/pull/notes/user-1", { withKeyring: true })
// result.data    → the (encrypted) notes document
// result.keyring → the matching _keyring document { data, hash, timestamp }
```

This is a narrow convenience — it always folds exactly one sibling.

### Projection — one list, one pull

When your "many documents" are really **one logical list** maintained by the server
after every write, use the `starfish-projection` extension. The server runs a pure
mapping after each push and keeps one list document up to date; clients pull that one
document regardless of how many items are in the list:

```
GET /pull/catalog/electronics
→ { "items": [ { "id": "prod-1", "value": {...} }, ... ] }
```

One pull, no fan-out. See [Projection](/extensions/projection) for setup.

Choose projection over `batchPull` when:
- The set of items is determined by the server (not the client choosing which to read).
- Items are created by writes to another collection (the projection watches that
  collection and maintains the list automatically).
- The list fits in one document (rule of thumb: up to ~thousands of entries).

### List, then batch pull

When you need to discover which documents exist before reading them, use the [list
endpoint](/server/list-endpoint) to enumerate keys under a prefix, then
`batchPull` the discovered keys:

```ts
// 1. Discover which days have messages for a group
const list = await client.fetch("/list/chats/group-abc")
// { items: ["2026-06-01", "2026-06-02", ...], hasMore: false }

// 2. Pull all of them in one batch
const entries = await client.batchPullMany(
  "chats",
  list.items.map((day) => ({ groupId: "group-abc", day })),
)
```

Total: 2 round-trips regardless of how many keys are found.

---

## Writing many at once

**There is no batch push / bulk-write endpoint.** Every write is a single-document
`POST /push/{path}` with an optimistic-concurrency `baseHash`; a hash mismatch returns
`409`. Even bundle "push" is one separate POST per bundle member — there is no atomic
multi-document write.

This is intentional: cross-document atomicity would require distributed transactions,
which conflict with the library's design goal of working against any object-store
backend. Design for **idempotency and eventual consistency** instead.

### Pattern 1 — bounded-concurrency fan-out

Run pushes concurrently but cap the concurrency to avoid overwhelming the server:

```ts
import { SyncManager } from "@drakkar.software/starfish-client"

async function pushMany<T>(
  managers: SyncManager<T>[],
  data: T[],
  concurrency = 5,
): Promise<PromiseSettledResult<void>[]> {
  const results: PromiseSettledResult<void>[] = []
  for (let i = 0; i < managers.length; i += concurrency) {
    const batch = managers.slice(i, i + concurrency)
    const batchData = data.slice(i, i + concurrency)
    const settled = await Promise.allSettled(
      batch.map((mgr, j) => mgr.push(batchData[j]!)),
    )
    results.push(...settled)
  }
  return results
}
```

Each `SyncManager.push` independently handles encryption, signing, conflict retry, and
merge — a conflict on one document does not affect the others.

### Pattern 2 — restructure into one document

If items are always written and read together, put them in one document instead of
many. One `client.push` covers all fields; a single `pull` reads them back. See the
[one-doc-vs-many decision table](/data-modeling/multi-document-architecture) for when this
makes sense.

### Pattern 3 — append-only collections

For high-frequency, high-volume writes (event streams, logs, per-item audit trails)
where each item is independent, use an append-only collection. Each `client.append`
call adds one entry; the server enforces a monotonic-timestamp contract and accumulates
items into the document without a `baseHash` optimistic-concurrency check:

```ts
await client.append("/push/events/room-42", {
  type: "message",
  text: "hello",
})
```

Multiple concurrent appends from different clients are safe — no conflicts.

---

## Keeping many documents fresh

### SSE + targeted re-fetch

Subscribe to the server's change stream and invalidate (then re-pull) documents when
they change:

```ts
import { subscribeChanges } from "@drakkar.software/starfish-client/events"

const unsub = subscribeChanges({
  url: "https://api.example.com/v1/myapp/events",
  onMessage(event) {
    const { collection, params } = event as { collection: string; params: Record<string, string> }
    // Re-pull the changed collection + its siblings in one batch
    client.batchPull([collection, "theme"], { params: { [collection]: [params] } })
      .then(applyToStores)
  },
})
```

See [SSE Subscribe Transport](/client-core/sse-subscribe) for the full options reference.

### Staleness and background revalidation

`SyncManager.pull` (and `StarfishClient.pull`) support `staleWhileRevalidate: true`
(added in 3.0.0-alpha.35): return a cached snapshot immediately and revalidate in the
background, so the UI is never blocked on a network round-trip. The refreshed result
is applied automatically when it arrives.

```ts
const syncManager = new SyncManager({
  client,
  pullPath: "/pull/notes/user-1",
  pushPath: "/push/notes/user-1",
})

// Returns stale data instantly; revalidates in background
await syncManager.pull({ staleWhileRevalidate: true })
```

---

## Python parity

Both `batch_pull` and `batch_pull_many` are available in
`starfish-sdk` (`packages/python/client`) with identical request/response shapes:

```python
from starfish_sdk import StarfishClient

client = StarfishClient(base_url="https://api.example.com")

result = await client.batch_pull(
    ["profile", "settings"],
    params={"profile": [{"identity": "user-1"}, {"identity": "user-2"}]},
)
# result["collections"]["profile"] → list of { "data", "hash", "timestamp" } | { "error" }

entries = await client.batch_pull_many(
    "profile",
    [{"identity": "user-1"}, {"identity": "user-2"}],
)
```

The [projection extension](/extensions/projection) is also available as
`starfish-projection` (Python) with a mirrored API.

---

## Design note: HTTP batch rather than GraphQL

GraphQL was evaluated as an alternative transport to enable multi-content sync and
rejected for these reasons:

1. **The bulk-read problem is already solved** by `/batch/pull`, bundles, and
   projection. Adding a new transport would duplicate work, not close a gap.

2. **Field selection is impossible on encrypted documents.** In `delegated` mode,
   documents are opaque AES-256-GCM ciphertext — the server holds no keys and cannot
   read inside a document to resolve fields. GraphQL's core value proposition (server-
   side field selection and graph traversal) does not apply.

3. **The HTTP server is not transport-agnostic at the auth layer.** Cap-cert
   authorization, rate-limiting, field-permission filtering, plugin dispatch, and audit
   logging are written directly against the Hono (TS) and FastAPI (Python) request
   context. Adding a parallel GraphQL transport would require re-implementing all of
   that, twice, with no shared abstraction.

4. **HTTP caching is load-bearing.** `GET /batch/pull` is CDN/HTTP-cacheable; the
   stale-while-revalidate work (alpha.35) depends on this. GraphQL-over-POST gives it
   up.

---

## Next Steps

- [Multi-Document Architecture](/data-modeling/multi-document-architecture) — when to use one
  document vs many; URL design; partitioning strategies
- [Projection](/extensions/projection) — server-maintained lists; one pull reads
  the whole list
- [List Endpoint](/server/list-endpoint) — enumerate keys under a prefix
- [SSE Subscribe Transport](/client-core/sse-subscribe) — real-time change notifications
- [KV Pull Cache](/state-offline/kv-pull-cache) — persist and reuse pull results across
  sessions
