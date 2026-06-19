> ⚠️ **Deprecated.** The Python implementation of Starfish is no longer maintained in
> parity with the TypeScript packages and will be **removed in a future release**.
> Use the TypeScript `@drakkar.software/starfish-*` packages instead.

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

## Authenticated replicas (`ReplicaAuth`)

When the primary requires cap-cert + Ed25519 request signing, wrap the replica's
HTTP client in `ReplicaAuth` — an `httpx.Auth` that signs every outgoing pull/push
request and attaches the cap + signature headers. The replica manager accepts an
injectable `client`, so pass an `AsyncClient` configured with the auth:

```python
import httpx
from starfish_replica import ReplicaAuth, ReplicaManager, create_replica_server_plugin

auth = ReplicaAuth(passphrase=PLATFORM_PASSPHRASE)
# Optional: cross-check the derived identity before trusting it.
assert auth.user_id == expected_user_id

client = httpx.AsyncClient(timeout=30.0, auth=auth)
replica = create_replica_server_plugin(
    store=store,
    sync_config=config,
    collections=collections,
    client=client,
)
```

Per request it bootstraps (once) a self-signed device cap-cert from the
passphrase — or accepts a pre-bootstrapped `credentials=DeviceCredentials` — then
attaches:

| Header | Value |
| --- | --- |
| `Authorization` | `Cap ` + base64(stable_stringify(cap-cert)) |
| `X-Starfish-Sig` | base64 Ed25519 signature over the canonical request bytes |
| `X-Starfish-Ts` | Unix milliseconds |
| `X-Starfish-Nonce` | base64 16-byte random nonce |

The cap-cert has a finite TTL (30 days by default). `ReplicaAuth` re-mints it
transparently when it nears expiry (`refresh_margin_sec`, default one day) so a
long-uptime replica never 401-storms — the signing key and userId are preserved
across refreshes. `scope` defaults to `scopes.root_all()`; pass a narrower
`ScopePreset` to restrict the cap.
