# starfish-projection

Materialized-view extension for Starfish (Python). After a successful push, the
server hands each registered plugin a `WriteEvent`; this plugin runs an
app-supplied **pure** mapping for each watched source collection and writes the
result into a **target** collection — an upsert, a delete, or nothing.

## Install

```sh
pip install starfish-server starfish-projection
```

## Usage

```python
from starfish_server import create_sync_router, SyncRouterOptions
from starfish_projection import (
    Projection, ProjectionUpsert, ProjectionDelete, create_projection_server_plugin,
)

def project(e):
    space_id = e.params["spaceId"]
    meta = e.body or {}
    if meta.get("discoverable") is not True:
        return ProjectionDelete(key=f"spacedir/{space_id}")
    return ProjectionUpsert(key=f"spacedir/{space_id}", data={"name": meta.get("name")})

plugin = create_projection_server_plugin(
    store=store,
    projections=[Projection(source=["pubspace", "spacediscovery"], project=project)],
)

router = create_sync_router(
    SyncRouterOptions(config=config, store=store, plugins=[plugin]),
)
```

`project(event)` returns a `ProjectionUpsert(key, data)` (upsert, last-writer-wins
by key), a `ProjectionDelete(key)` (delete), or `None` (ignore). `project` may be
sync or async.

The view is written in-process against the store, never over HTTP, so the target
collection can be declared `pull_only=True` — clients read/enumerate it, but only
the projection writes it. Pair it with `listable=True` + `list_values=True` so a
client can fetch the whole view in one `GET /list/<target>?include=values`.

Projection failures are logged and never break the originating client write.

See `docs/ts/projection/` for the full guide (the TypeScript and Python APIs
mirror each other).
