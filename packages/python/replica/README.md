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

## Channels: `ReplicaChannel` and the scheduler

`ReplicaManager` is a thin subclass of `ChannelScheduler`. The scheduler owns
the interval loop, the `on_pull` cooldown and the error funnel; a
**channel** owns one data path and knows how to sync itself once:

```python
class ReplicaChannel(Protocol):
    name: str
    async def sync(self, ctx: ReplicaCallContext) -> None: ...
```

`HttpReplicaChannel` is the original primary→replica HTTP path.
`ReplicaManager(store, collections, ...)` builds one per `RemoteCollection`,
so its constructor and behaviour are unchanged. To schedule your own
channels, use `ChannelScheduler` directly (or `ReplicaManager.from_channels`).

## `starfish_replica.space` — mirror into a Starfish space

A second channel: instead of pulling a primary's document into a local
`ObjectStore`, it pushes an app-local projection into per-collection nodes of
one or more Starfish spaces, encrypted under each space's keyring.

```bash
pip install "starfish-replica[space]"   # pulls starfish-spaces
```

```python
from starfish_replica.channel import ChannelSchedule, ScheduledChannel, SyncTrigger
from starfish_replica.scheduler import ChannelScheduler
from starfish_replica.space import SpaceMirrorCollection, create_space_mirror_channel

channel = create_space_mirror_channel(
    name="cloud-mirror",
    session=session,                       # a starfish_spaces session
    collections=[
        SpaceMirrorCollection(id="accounts", space_name="app-mirror"),
        SpaceMirrorCollection(id="settings", space_name="app-mirror-private"),
    ],
    enabled_ids=lambda: settings.enabled_collection_ids,   # re-read every cycle
    read_source=lambda cid, ctx: load_projection(cid),
    doc_path=lambda space_id, node_id: f"spaces/{space_id}/objects/mirror/{node_id}",
)

scheduler = ChannelScheduler([
    ScheduledChannel(
        channel=channel,
        schedule=ChannelSchedule(triggers=[SyncTrigger.SCHEDULED], interval_ms=300_000),
    )
])
await scheduler.start()
```

Each cycle: resolve (or create) each space → read its object tree → diff
against `enabled_ids` → create missing nodes → CAS-write each enabled
collection's projection → clear the content of nodes whose collection was
turned off. `channel.result` reports
`spaces`/`created`/`written`/`skipped`/`cleared` for the last cycle.

- **`node_enc`** defaults to `{"access": "space", "enc": True}`. `"invite"`
  access is deliberately not the default: it resolves through a per-node
  keyring nothing in a mirror-style writer ever seeds.
- **`change_detection`** defaults to `"none"` (write every cycle).
  `"source-hash"` skips a write when the source projection is unchanged —
  **only safe when this channel is the sole writer of that node**, since a
  skip means the channel never re-checks what is actually stored.
- Writes go through `SpacePort.push_node_doc`, which retries on CAS conflict
  via `starfish_spaces.cas_retry.run_cas`.
- `port=` swaps the whole `starfish_spaces` surface for tests;
  `space/port.py` is the only module that imports it.

### Not implemented: the read side

This subpackage is **write-only**. The TypeScript subpath additionally exports
`readSpaceMirror` — a session-less reader that, given a member cap for the
space plus ephemeral keys, pulls and decrypts every node it recognizes. There
is no Python equivalent yet.

This is a gap, not a design position: the two sides are independent, and a
reader is a reasonable thing to want. It has not been written because it needs
a part of `starfish_spaces` that a writer never exercises — invite/link-cap
resolution and per-node keyrings (`get_node_access` tiers 1 and 3), which the
Python package covers less completely than the TypeScript one. Writing a
reader means filling that in first.

Until then, read mirrored content with the TypeScript
`@drakkar.software/starfish-replica/space` reader, or against the space's
node documents directly via `starfish_spaces`.
