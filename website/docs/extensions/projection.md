---
sidebar_position: 8
sidebar_label: "Projection"
---

# Projection (Incremental Lists)

`starfish-projection` is the incremental-list extension. After every successful
push, the server hands each registered plugin a `WriteEvent`; the projection plugin
runs an app-supplied **pure** mapping for each watched source collection and folds
the result into a single **list document** — appending a new entry, updating one in
place, or removing it. Clients then pull that one document to read the whole list.

It lives in its own package — `@drakkar.software/starfish-projection` (TS) /
`starfish-projection` (Python) — and hooks into the server through the
`ServerPlugin.afterWrite` contract, exactly like `starfish-queuing`. Unlike queuing,
it writes back to the object store, so it depends on `starfish-server` for the `pull`
/ `push` helpers and the `ObjectStore` type.

## Why

It generalizes a common pattern: *on write to collection X, maintain a denormalized
list of entries in document Y; create appends, updates patch, deletes remove.* A
product catalog, a per-user index, or a public directory are all the same shape.
Instead of each app building a bespoke indexer (subscribe to a queue, run a
privileged client, manage the list), the app supplies only the mapping and the
plugin owns all store IO — including the concurrency-safe read-modify-write.

The client side is the point: one collection holds the whole list, so the consumer
issues a single `GET /pull/<list>` instead of listing a directory of keys and then
pulling each one.

## How it works

1. Build the plugin with the same `store` the router uses and a list of projections:
   `createProjectionServerPlugin({ store, projections })`.
2. Pass it to `createSyncRouter` via `SyncRouterOptions.plugins`.
3. On every successful push (HTTP 200) to a collection named in a projection's
   `source`, the plugin resolves the `target` list, calls `project(event)`, and folds
   the entry op into that list document.

Projection failures never surface to clients — they are logged and the originating
push response is returned normally (same contract as `afterWrite`).

## Projection

```ts
interface Projection {
  /** Source collection name(s) whose writes trigger this projection. */
  source: string | string[]
  /** The list document to maintain — a fixed storage key, or a function of the
   *  event (return null to ignore the event, or a per-bucket key to shard). */
  target: string | ((event: WriteEvent) => string | null)
  /** Pure mapping from a source write event to an entry op. */
  project: (event: WriteEvent) =>
    | { id: string; value: Record<string, unknown> } // UPSERT entry `id`
    | { id: string; remove: true }                    // REMOVE entry `id`
    | null                                            // IGNORE this event
}
```

`event` is the standard `WriteEvent`: `collection`, `params`, optional `body` (the
pushed JSON document), `hash`, `timestamp`, and optional `identity`. `params` is
always present; `body` is present for JSON pushes.

The list document is stored as an insertion-ordered array under the resolved
`target` key:

```jsonc
{ "items": [ { "id": "a", "value": { "name": "Alpha" } }, … ] }
```

`id` is held **alongside** `value`, never merged into it — so a `value.id` field can
never clobber the entry's identity.

## Server setup

```ts
import { createSyncRouter } from "@drakkar.software/starfish-server"
import { createProjectionServerPlugin } from "@drakkar.software/starfish-projection"

const projection = createProjectionServerPlugin({
  store,
  projections: [
    {
      source: "products",
      // One list document per tenant keeps each list bounded.
      target: (e) => `catalog/${e.params.tenant}`,
      project: (e) => {
        const meta = e.body ?? {}
        // A tombstone push removes the entry; everything else upserts it.
        if (meta.deleted === true) return { id: e.params.id, remove: true }
        return { id: e.params.id, value: { name: meta.name, tags: meta.tags ?? [] } }
      },
    },
  ],
})

const router = createSyncRouter({ store, config, roleResolver, plugins: [projection] })
```

There is **no delete route** on the server, so a removal is signalled by a normal
write whose body your mapping recognises as a deletion (a tombstone) — here
`{ deleted: true }`.

## The `pullOnly` target pattern (indexer-owned lists)

The list is written **in-process**, directly against the store — never over HTTP.
So the target collection can be declared `pullOnly: true`: clients can read it, but
the server registers **no push route**, so no client can write or tamper with it.
Only the projection populates it. This is how a list becomes "owned by the indexer"
without any new capability kind or role:

```ts
{
  name: "catalog",
  storagePath: "catalog/{tenant}",
  readRoles: ["member"],
  writeRoles: [],            // no client writes (pullOnly makes this explicit)
  encryption: "none",
  maxBodyBytes: 1_000_000,
  pullOnly: true,            // ← only the projection writes it
}
```

A client reads the entire list in one request: `GET /pull/catalog/<tenant>`.

## Semantics

- **Upsert** (`{ id, value }`): if no entry with `id` exists it is appended at the
  end; if one exists its `value` is **fully replaced** in place (its position is
  preserved, not moved to the end).
- **Remove** (`{ id, remove: true }`): the entry with `id` is spliced out (a no-op if
  absent). Emptying the list leaves an empty `{ items: [] }` document — it is never
  deleted, so a reader always gets a document rather than a 404.
- **Ignore** (`null`, or a `target` function returning `null`) leaves the list
  untouched.
- A projection only fires for collections listed in its `source`.

### Concurrency

Many source writes can target the same list at once, so each apply is a
compare-and-set loop: the plugin re-pulls the list, folds the entry in, and pushes
with the pulled hash. `push` rejects on a stale hash, so on a conflict (a concurrent
write landed first) the plugin re-pulls and re-applies onto fresh state rather than
clobbering it. No update is lost. `maxRetries` (default 8) bounds the loop; on
exhaustion the op is logged and dropped.

### Scale

Every write rewrites and re-hashes the **whole** list document under one per-key
lock, and in-process pushes bypass the HTTP `maxBodyBytes` limit — so an unbounded
list can grow without limit and make each write progressively more expensive. Keep
lists bounded:

- **Shard** with a `target` function — one list per tenant/bucket (the example
  above). This is the primary lever for large views.
- Set **`maxItems`** as a safety cap: once a list is full, further *appends* are
  logged and dropped (existing entries are never evicted; updates and removes still
  apply).

This model fits lists of up to ~thousands of entries per target. For very large or
unbounded collections, keep per-document storage and enumerate with the
[list endpoint](/server/list-endpoint) instead.

## Sharding a list across documents

When one logical list would grow too large for a single document, split it by a
**natural key** — give `target` a function that returns one key per shard. Each
shard is an independent list document with its own CAS lock and its own `maxItems`
cap, so writes spread across shards instead of contending on one hot document. A
product catalog, for example, shards cleanly by category:

```ts
{
  source: "products",
  // One list per category; skip a write with no category.
  target: (e) => (e.body?.category ? `catalog/${e.body.category}` : null),
  project: (e) => e.body?.deleted === true
    ? { id: e.params.id, remove: true }
    : { id: e.params.id, value: { name: e.body?.name, price: e.body?.price } },
}
```

Register the shard collection so clients can read it — `pullOnly` (only the
projection writes it) and `listable` (so the shards can be enumerated):

```ts
{
  name: "catalog",
  storagePath: "catalog/{category}",   // the last segment is the shard key
  readRoles: ["member"],
  writeRoles: [],                      // no client writes
  encryption: "none",
  maxBodyBytes: 1_000_000,
  pullOnly: true,
  listable: true,                      // enables GET /list/catalog
}
```

**Client fetch** — two shapes, matching how you actually query:

- **One shard** (the common case, e.g. a category view) — pull it directly:
  ```
  GET /pull/catalog/electronics    → { items: [ { id, value }, … ] }
  ```
- **The whole list** — discover the shards via the list endpoint, then pull each and
  concatenate:
  ```
  GET /list/catalog                → { items: ["books", "electronics"] }
  GET /pull/catalog/books          → { items: [ … ] }
  GET /pull/catalog/electronics    → { items: [ … ] }
  ```
  That is `1 + shardCount` requests — bounded by the number of shards, not the
  number of entries.

> **Caveat — shard by an _immutable_ key.** The plugin sees only the current write,
> so if an entry's shard key can change (a product re-categorised from `books` to
> `electronics`), it writes the entry into the new shard but cannot remove it from
> the old one, leaving a stale copy. Shard by something fixed at creation (an
> `ownerId`, a `categoryId` assigned once) and keep any mutable, human-facing label
> as a field inside `value` that the client filters on.

## Python

The Python API mirrors the TypeScript one. `project` returns a `ProjectionSet`, a
`ProjectionRemove`, or `None`, and may be sync or async:

```python
from starfish_projection import (
    Projection, ProjectionSet, ProjectionRemove, create_projection_server_plugin,
)

def project(e):
    meta = e.body or {}
    if meta.get("deleted") is True:
        return ProjectionRemove(id=e.params["id"])
    return ProjectionSet(
        id=e.params["id"],
        value={"name": meta.get("name"), "tags": meta.get("tags", [])},
    )

plugin = create_projection_server_plugin(
    store=store,
    projections=[
        Projection(
            source="products",
            target=lambda e: f"catalog/{e.params['tenant']}",
            project=project,
        )
    ],
    max_items=None,   # optional safety cap
)
```

## Next Steps

- [List Endpoint](/server/list-endpoint) — enumerate keys of a per-document
  collection, the alternative when a list is too large to hold in one document
- [Queuing](/extensions/queuing) — publish change events off-box instead of (or
  alongside) projecting them
