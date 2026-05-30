# @drakkar.software/starfish-projection

Materialized-view extension for Starfish. After a successful push, the server
hands each registered plugin a `WriteEvent`; this plugin runs an app-supplied
**pure** mapping for each watched source collection and writes the result into a
**target** collection — an upsert, a delete, or nothing.

Use it to maintain a denormalized index/directory/rollup from a source of truth
without building a bespoke indexer: the app supplies only the mapping, the plugin
owns all store IO.

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
          source: ["pubspace", "spacediscovery"],
          project: (e) =>
            e.body?.discoverable === true
              ? { key: `spacedir/${e.params.spaceId}`, data: { name: e.body.name } }
              : { key: `spacedir/${e.params.spaceId}`, delete: true },
        },
      ],
    }),
  ],
})
```

A projection's `project(event)` returns one of:

- `{ key, data }` — **upsert** the target document at storage key `key`
  (last-writer-wins by key),
- `{ key, delete: true }` — **delete** the target document,
- `null` — **ignore** the event.

The view is written in-process against the store, never over HTTP, so the target
collection can be declared `pullOnly: true` — clients read/enumerate it, but only
the projection writes it. Pair it with `listable` + `listValues` so a client can
fetch the whole view (keys + content) in one `GET /list/<target>?include=values`.

Projection failures are logged and never break the originating client write (same
contract as `starfish-queuing`'s `afterWrite`).

See `docs/ts/projection/` for the full guide (the TypeScript and Python APIs
mirror each other).
