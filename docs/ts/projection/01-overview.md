# Projection (Materialized Views)

`starfish-projection` is the materialized-view extension. After every successful
push, the server hands each registered plugin a `WriteEvent`; the projection plugin
runs an app-supplied **pure** mapping for each watched source collection and writes
the result into a **target** collection — an UPSERT, a DELETE, or nothing.

It lives in its own package — `@drakkar.software/starfish-projection` (TS) /
`starfish-projection` (Python) — and hooks into the server through the
`ServerPlugin.afterWrite` contract, exactly like `starfish-queuing`. Unlike queuing,
it writes back to the object store, so it depends on `starfish-server` for the `pull`
/ `push` helpers and the `ObjectStore` type.

## Why

It generalizes a common pattern: *on write to collection X, derive a denormalized
document into collection Y, and remove it when some condition no longer holds.* A
search/discovery index, a per-user rollup, or a public directory are all the same
shape. Instead of each app building a bespoke indexer (subscribe to a queue, run a
privileged client, manage upserts/deletes), the app supplies only the mapping and the
plugin owns all store IO.

## How it works

1. Build the plugin with the same `store` the router uses and a list of projections:
   `createProjectionServerPlugin({ store, projections })`.
2. Pass it to `createSyncRouter` via `SyncRouterOptions.plugins`.
3. On every successful push (HTTP 200) to a collection named in a projection's
   `source`, the plugin calls `project(event)` and applies the outcome to `store`.

Projection failures never surface to clients — they are logged and the originating
push response is returned normally (same contract as `afterWrite`).

## Projection

```ts
interface Projection {
  /** Source collection name(s) whose writes trigger this projection. */
  source: string | string[]
  /** Pure mapping from a source write event to a target upsert/delete/ignore. */
  project: (event: WriteEvent) =>
    | { key: string; data: Record<string, unknown> } // UPSERT at storage key `key`
    | { key: string; delete: true }                   // DELETE the target document
    | null                                            // IGNORE this event
}
```

`event` is the standard `WriteEvent`: `collection`, `params`, optional `body` (the
pushed JSON document), `hash`, `timestamp`, and optional `identity`. `params` is
always present; `body` is present for JSON pushes.

The `key` you return is a full storage key (the resolved `storagePath` of the target
collection, e.g. `spacedir/sp-123`), not a route path.

## Server setup

```ts
import { createSyncRouter } from "@drakkar.software/starfish-server"
import { createProjectionServerPlugin } from "@drakkar.software/starfish-projection"

const projection = createProjectionServerPlugin({
  store,
  projections: [
    {
      source: ["pubspace", "spacediscovery"],
      project: (e) => {
        const spaceId = e.params.spaceId
        const meta = e.body ?? {}
        // Only index discoverable spaces; otherwise remove any stale entry.
        if (meta.discoverable !== true) return { key: `spacedir/${spaceId}`, delete: true }
        return {
          key: `spacedir/${spaceId}`,
          data: { id: spaceId, name: meta.name, tags: meta.tags ?? [] },
        }
      },
    },
  ],
})

const router = createSyncRouter({ store, config, roleResolver, plugins: [projection] })
```

## The `pullOnly` target pattern (indexer-owned views)

The view is written **in-process**, directly against the store — never over HTTP.
So the target collection can be declared `pullOnly: true`: clients can read it (and
enumerate it if `listable`), but the server registers **no push route**, so no client
can write or tamper with it. Only the projection populates it. This is how a target
becomes "owned by the indexer" without any new capability kind or role:

```ts
{
  name: "spacedir",
  storagePath: "spacedir/{spaceId}",
  readRoles: ["public"],     // public directory
  writeRoles: [],            // no client writes (pullOnly makes this explicit)
  encryption: "none",
  maxBodyBytes: 65536,
  pullOnly: true,            // ← only the projection writes it
  listable: true,
  listValues: true,          // ← enumerate the whole view in one request
}
```

Pair `listValues` (see [the list endpoint](../server/list-endpoint.md)) with the
view so a client fetches the entire directory — keys *and* content — in a single
`GET /list/spacedir?include=values`.

## Semantics

- **Upsert** is last-writer-wins by key: the plugin reads the current hash and writes
  with it as `baseHash`, so a re-projection overwrites the previous value rather than
  conflicting. The stored document is byte-identical to a normal pushed document, so
  pull / list-with-values / batch-pull read it back unchanged.
- **Delete** removes the target document (idempotent — deleting a missing key is a
  no-op).
- **Ignore** (`null`) leaves the view untouched.
- A projection only fires for collections listed in its `source`.

## Python

The Python API mirrors the TypeScript one. `project` returns a `ProjectionUpsert`,
a `ProjectionDelete`, or `None`:

```python
from starfish_projection import (
    Projection, ProjectionUpsert, ProjectionDelete, create_projection_server_plugin,
)

def project(e):
    space_id = e.params["spaceId"]
    meta = e.body or {}
    if meta.get("discoverable") is not True:
        return ProjectionDelete(key=f"spacedir/{space_id}")
    return ProjectionUpsert(
        key=f"spacedir/{space_id}",
        data={"id": space_id, "name": meta.get("name"), "tags": meta.get("tags", [])},
    )

plugin = create_projection_server_plugin(
    store=store,
    projections=[Projection(source=["pubspace", "spacediscovery"], project=project)],
)
```

## Next Steps

- [List Endpoint](../server/list-endpoint.md) — `?include=values` to enumerate a view
- [Queuing](../queuing/01-overview.md) — publish change events off-box instead of (or
  alongside) projecting them
