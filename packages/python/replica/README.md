# starfish-replica

Replication extension for [Starfish](https://github.com/Drakkar-Software/starfish). Lets you run
multiple Starfish servers that stay in sync: a **primary** holds the source of truth; **replicas**
pull from it and serve reads locally.

Shipped as a `ServerPlugin` — it owns its own config (the `remote` field is no longer part of the
core `CollectionConfig`).

## Install

```bash
pip install starfish-replica
```

## Usage

```python
from starfish_server import create_sync_router, SyncRouterOptions
from starfish_replica import create_replica_server_plugin, RemoteConfig

replica = create_replica_server_plugin(
    store=store,
    sync_config=config,
    collections={
        # keyed by root collection name
        "posts": RemoteConfig(
            url="https://primary.example.com/v1",
            pullPath="/pull/posts/featured",
            interval_ms=60_000,
            headers={"Authorization": "Bearer <replica-token>"},
            write_mode="pull_only",        # clients can't push to this replica
            sync_triggers=["scheduled"],   # or ["on_pull"]
        ),
    },
)

router = create_sync_router(SyncRouterOptions(
    store=store,
    config=config,
    role_resolver=role_resolver,
    plugins=[replica.plugin],  # + other plugins
))

await replica.manager.start()  # begin scheduled / initial syncs
# on shutdown: register replica.plugin in GracefulShutdownOptions(plugins=[...])
```

## Write modes

| Mode | Client reads | Client writes | Syncs from primary |
| --- | --- | --- | --- |
| `pull_only` | ✓ | rejected (405) | ✓ replace |
| `push_through` | ✓ | forwarded to primary | ✓ replace |
| `bidirectional` | ✓ | stored locally | ✓ merge (remote-wins) |
| `push_only` | rejected (405) | stored locally | — |

`push_through` and `bidirectional` require `push_path`.
