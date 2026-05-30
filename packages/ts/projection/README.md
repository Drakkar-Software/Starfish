# @drakkar.software/starfish-projection

Incremental-list extension for Starfish. After a successful push, the server
hands each registered plugin a `WriteEvent`; this plugin runs an app-supplied
**pure** mapping for each watched source collection and folds the result into a
single **list document** — appending a new entry, updating one in place, or
removing it.

Use it to maintain a denormalized list/index/directory from a source of truth
without building a bespoke indexer: the app supplies only the mapping, the plugin
owns all store IO. The client then pulls **one document** to read the whole list,
instead of enumerating a directory of per-entry documents.

## Install

```sh
pnpm add @drakkar.software/starfish-server @drakkar.software/starfish-projection
```

## Usage

```ts
import { createSyncRouter } from "@drakkar.software/starfish-server"
import { createProjectionServerPlugin } from "@drakkar.software/starfish-projection"

const router = createSyncRouter({
  config,
  store,
  // …
  plugins: [
    createProjectionServerPlugin({
      store,
      projections: [
        {
          source: "products",
          // One list document per tenant keeps each list bounded.
          target: (e) => `catalog/${e.params.tenant}`,
          project: (e) =>
            e.body?.deleted === true
              ? { id: e.params.id, remove: true }
              : { id: e.params.id, value: { name: e.body?.name } },
        },
      ],
    }),
  ],
})
```

A projection's `project(event)` returns one of:

- `{ id, value }` — **upsert**: append a new entry `{ id, value }` to the target
  list, or replace an existing entry's `value` in place (keeping its position),
- `{ id, remove: true }` — **remove** the entry with this `id` (a no-op if
  absent). There is no delete route on the server, so a removal is signalled by a
  normal write whose body your mapping recognises as a deletion (a tombstone),
- `null` — **ignore** the event.

The list is stored as `{ items: [{ id, value }, …] }` in insertion order — `id`
is held alongside `value` (never merged into it, so a `value.id` field can't
clobber it). `target` is either a fixed storage key or a function of the event;
return `null` from the function to ignore the event, or a per-bucket key to
**shard** a large view into many small lists.

The list is written in-process against the store, never over HTTP, so the target
collection can be declared `pullOnly: true` — clients read it, but only the
projection writes it.

### Concurrency & scale

Many source writes can target the same list at once, so each apply is a
compare-and-set loop: the plugin re-pulls the list, folds the entry in, and
pushes with the pulled hash; on a hash mismatch (a concurrent write landed first)
it re-pulls and re-applies rather than clobbering. No update is lost.

Every write rewrites and re-hashes the **whole** list document under one per-key
lock, and in-process pushes bypass the HTTP `maxBodyBytes` limit, so an unbounded
list can grow without limit and make each write progressively more expensive.
Keep lists bounded:

- **Shard** with a `target` function — one list per tenant/bucket (the example
  above), the primary lever for large views.
- Set **`maxItems`** as a safety cap: once a list is full, further *appends* are
  logged and dropped (existing entries are never evicted; updates and removes
  still apply).

`maxRetries` (default 8) bounds the CAS loop; on exhaustion the op is logged and
dropped. Projection failures are logged and never break the originating client
write (same contract as `starfish-queuing`'s `afterWrite`).

See `docs/ts/projection/` for the full guide (the TypeScript and Python APIs
mirror each other).
