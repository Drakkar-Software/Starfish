> ⚠️ **Deprecated.** The Python implementation of Starfish is no longer maintained in
> parity with the TypeScript packages and will be **removed in a future release**.
> Use the TypeScript `@drakkar.software/starfish-*` packages instead.

# starfish-projection

Incremental-list extension for Starfish (Python). After a successful push, the
server hands each registered plugin a `WriteEvent`; this plugin runs an
app-supplied **pure** mapping for each watched source collection and folds the
result into a single **list document** — appending a new entry, updating one in
place, or removing it. The client then pulls one document to read the whole list.

## Install

```sh
pip install starfish-server starfish-projection
```

## Usage

```python
from starfish_server import create_sync_router, SyncRouterOptions
from starfish_projection import (
    Projection, ProjectionSet, ProjectionRemove, create_projection_server_plugin,
)

def project(e):
    meta = e.body or {}
    if meta.get("deleted") is True:
        return ProjectionRemove(id=e.params["id"])
    return ProjectionSet(id=e.params["id"], value={"name": meta.get("name")})

plugin = create_projection_server_plugin(
    store=store,
    projections=[
        Projection(
            source="products",
            # One list document per tenant keeps each list bounded.
            target=lambda e: f"catalog/{e.params['tenant']}",
            project=project,
        )
    ],
)

router = create_sync_router(
    SyncRouterOptions(config=config, store=store, plugins=[plugin]),
)
```

`project(event)` returns one of:

- `ProjectionSet(id, value)` — **upsert**: append a new entry `{id, value}` to the
  target list, or replace an existing entry's `value` in place (keeping its
  position),
- `ProjectionRemove(id)` — **remove** the entry with this `id` (a no-op if absent).
  There is no delete route on the server, so a removal is signalled by a normal
  write whose body your mapping recognises as a deletion (a tombstone),
- `None` — **ignore** the event.

`project` may be sync or async. The list is stored as
`{"items": [{"id", "value"}, …]}` in insertion order — `id` is held alongside
`value`, never merged into it. `target` is a fixed storage key or a function of
the event; return `None` from the function to ignore the event, or a per-bucket
key to **shard** a large view into many small lists.

The list is written in-process against the store, never over HTTP, so the target
collection can be declared `pull_only=True` — clients read it, but only the
projection writes it.

### Concurrency & scale

Many source writes can target the same list at once, so each apply is a
compare-and-set loop: the plugin re-pulls the list, folds the entry in, and
pushes with the pulled hash; on a hash mismatch (a concurrent write landed first)
it re-pulls and re-applies rather than clobbering. No update is lost.

Every write rewrites and re-hashes the **whole** list document under one per-key
lock, and in-process pushes bypass the HTTP `max_body_bytes` limit, so an
unbounded list can grow without limit. Keep lists bounded — **shard** with a
`target` function (one list per tenant/bucket), and optionally set `max_items` as
a safety cap (once full, further appends are logged and dropped; updates and
removes still apply). `max_retries` (default 8) bounds the CAS loop.

Projection failures are logged and never break the originating client write.

See `docs/ts/projection/` for the full guide (the TypeScript and Python APIs
mirror each other).
