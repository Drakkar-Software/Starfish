---
sidebar_position: 10
sidebar_label: "Replica"
---

# Replication

`starfish-replica` is the replication extension. It lets you run multiple
Starfish servers that stay in sync: a **primary** server holds the source of
truth; **replicas** pull from it and serve reads locally (and optionally accept
local writes, forwarding or merging them).

It lives in its own package — `@drakkar.software/starfish-replica` (TS) /
`starfish-replica` (Python) — and hooks into the server through the
`ServerPlugin` route hooks (`beforePull` / `interceptPush`) plus the `shutdown`
hook. The replica config (`remote`) is **no longer part of `CollectionConfig`**;
the plugin owns it, exactly like `starfish-queuing` owns its `QueueConfig`.

Unlike the client-side cap extensions, `starfish-replica`'s root `.` entry
depends on `starfish-server` — the default `HttpReplicaChannel` writes pulled
data through the server's `push()` (hash-based conflict detection) into the
`ObjectStore`. A second, independent data path at the `./space` subpath
mirrors into a Starfish *space* instead and never imports `starfish-server` —
see [Mirroring into a Starfish space](#mirroring-into-a-starfish-space) below.

Under the hood, scheduling (interval loop, on_pull cooldown, error funnel) is
a pure `ChannelScheduler` that drives whichever `ReplicaChannel` you give it —
`HttpReplicaChannel` (this path) or `SpaceMirrorChannel` (the `./space` path)
are just two implementations of that one interface. The root `.` entry's
`ReplicaManager` EXTENDS `ChannelScheduler` and adds the HTTP back-compat
constructor (`new ReplicaManager(store, collections, opts)`, unchanged) plus
`remoteFor`/`proxyPush`; `./space`'s own `ReplicaManager` export IS
`ChannelScheduler` directly — same scheduling API, but importing it never
pulls in `starfish-server` (the root one's `ReplicaManager` always does,
because its legacy constructor statically needs `HttpReplicaChannel`).

## How it works

1. Build the plugin with the store, the sync config, and a per-collection
   `RemoteConfig` map: `createReplicaServerPlugin({ store, syncConfig, collections })`.
   The factory validates the config (cross-referencing each remote against its
   collection) and throws on conflict.
2. Pass `plugin` to `createSyncRouter` via `SyncRouterOptions.plugins`, and pass
   it to `createGracefulShutdown({ plugins })` so its `shutdown` hook stops the
   sync timers.
3. Call `plugin.manager.start()` to begin scheduled/initial syncs.

On the request path:
- **Pull** — the route calls every plugin's `beforePull`. The replica plugin
  rejects pulls on a `push_only` collection (405), and on the `on_pull` trigger
  it syncs from the primary before the local read so the response is fresh.
- **Push** — the route calls every plugin's `interceptPush`. The replica plugin
  rejects pushes on a `pull_only` collection (405) and, for `push_through`,
  proxies the write to the primary and relays the response (then syncs back).

## Write modes

| Mode | Client reads | Client writes | Syncs from primary |
| --- | --- | --- | --- |
| `pull_only` (default) | ✓ | rejected (405) | ✓ replace |
| `push_through` | ✓ | forwarded to primary | ✓ replace |
| `bidirectional` | ✓ | stored locally | ✓ merge (remote-wins) |
| `push_only` | rejected (405) | stored locally | — |

`push_through` and `bidirectional` require `pushPath`.

## RemoteConfig

```ts
interface RemoteConfig {
  url: string                  // Base URL of the primary, e.g. https://primary.example.com/v1
  pullPath: string             // Static pull path on the primary (no template variables)
  pushPath?: string            // Required for push_through / bidirectional
  intervalMs: number           // Scheduled sync interval
  headers: Record<string, string>  // Static headers (e.g. Authorization) sent to the primary
  writeMode: WriteMode         // pull_only | push_through | bidirectional | push_only
  syncTriggers: SyncTrigger[]  // ["scheduled"] and/or ["on_pull"]
  onPullMinIntervalMs?: number // Cooldown between on_pull-triggered syncs
}
```

A remote collection must have a **static** `storagePath` (no `{template}`
params), must not be `pushOnly`, in a `bundle`, `appendOnly`, binary, or use
`"delegated"` encryption — the plugin enforces all of these at construction.

## Server setup

```ts
import { createSyncRouter, createGracefulShutdown } from "@drakkar.software/starfish-server"
import { createReplicaServerPlugin } from "@drakkar.software/starfish-replica"

const replica = createReplicaServerPlugin({
  store,
  syncConfig: config,
  collections: {
    posts: {
      url: "https://primary.example.com/v1",
      pullPath: "/pull/posts/featured",
      intervalMs: 60_000,
      headers: { Authorization: "Bearer <replica-token>" },
      writeMode: "pull_only",
      syncTriggers: ["scheduled"],
    },
  },
})

const sync = createSyncRouter({ store, config, roleResolver, plugins: [replica] })

replica.manager.start()

// shutdown hook stops the sync timers when plugins are passed here:
const handle = createGracefulShutdown({ plugins: [replica] })
```

The Python API mirrors this: `create_replica_server_plugin(store=..., sync_config=..., collections={...})`
returns an object with `.plugin` (pass to `SyncRouterOptions(plugins=[replica.plugin])`)
and `.manager` (`await replica.manager.start()`).

## Authenticated replicas

A static `headers` map covers bearer-token primaries. When the primary requires
cap-cert + Ed25519 per-request signing, use the built-in request-signing client
instead of hand-rolling it:

```ts
import { createReplicaAuth, ReplicaManager } from "@drakkar.software/starfish-replica"

// Bootstraps a self-signed device cap-cert from the passphrase (or pass a
// pre-bootstrapped `credentials: DeviceCredentials`).
const auth = await createReplicaAuth({ passphrase: PLATFORM_PASSPHRASE })
if (auth.userId !== expectedUserId) throw new Error("identity mismatch")

const manager = new ReplicaManager(store, collections, { fetchFn: auth.fetch })
```

`auth.fetch` signs every outgoing pull/push: it attaches
`Authorization: Cap <base64(cap-cert)>` plus `X-Starfish-Sig`/`-Ts`/`-Nonce`
over the canonical request bytes. The cap-cert (default 30-day TTL) is re-minted
transparently as it nears expiry (`refreshMarginSec`, default one day) so a
long-uptime replica never 401-storms; the signing key and `userId` are preserved
across refreshes. `scope` defaults to `scopes.rootAll()`.

Python mirrors this with `ReplicaAuth`, an `httpx.Auth`:

```python
import httpx
from starfish_replica import ReplicaAuth, ReplicaManager

auth = ReplicaAuth(passphrase=PLATFORM_PASSPHRASE)
client = httpx.AsyncClient(timeout=30.0, auth=auth)
manager = ReplicaManager(store, collections, client=client)
```

## Mirroring into a Starfish space

The primary→replica-server path above assumes both ends run `starfish-server`.
A different shape of problem — replicating a mobile app's or a node's own
local data into per-collection nodes of a Starfish *space*, encrypted under
that space's own keyring, so a third party can be granted read-only access
via `starfish-spaces`' `inviteToSpace` — is a second, independent
`ReplicaChannel` at the `./space` subpath. It depends on
`@drakkar.software/starfish-spaces` (an optional peer dependency) and never
imports `starfish-server`, so it's safe to bundle into a mobile or browser
client.

```ts
import { createSpaceMirrorChannel, ReplicaManager } from "@drakkar.software/starfish-replica/space"

const channel = createSpaceMirrorChannel({
  name: "cloud-mirror",
  session,                                    // a starfish-spaces Session
  collections: [{ id: "user-accounts", spaceName: "app-mirror" }],
  enabledIds: () => currentlyEnabledCollectionIds(),
  readSource: (id, ctx) => readLocalCollection(id),
  docPath: (spaceId, nodeId) => `spaces/${spaceId}/objects/mirror/${nodeId}`,
})

const manager = new ReplicaManager([
  { channel, schedule: { triggers: ["scheduled"], intervalMs: 5 * 60_000 } },
])
manager.start()

channel.result  // { spaces, created, written, skipped, cleared } after the last sync
```

`ReplicaManager` here is imported from `./space`, not the root `.` entry — see
the note above: it is `ChannelScheduler` directly, so this whole example never
touches `starfish-server`.

`SpaceMirrorChannel` finds-or-creates one space per distinct `spaceName` in
`collections`, finds-or-creates one node per collection id (`access: "space",
enc: true` by default), and CAS-writes `readSource`'s result into it every
cycle — `changeDetection` defaults to `"none"` (always write) since a
source-hash skip is only sound when this channel is the *sole* writer of a
node.

The read side, `readSpaceMirror`, is session-less: given a member cap for the
space (e.g. minted via `inviteToSpace`) plus the grant holder's own ephemeral
keys, it pulls and decrypts every node it recognizes. No `.` (`ReplicaManager`)
type or plugin machinery is involved on this side — it's a standalone function.

### Python

Python has the same channel, as `starfish_replica.space`, installed via the
`space` extra:

```bash
pip install "starfish-replica[space]"
```

```python
from starfish_replica.space import SpaceMirrorCollection, create_space_mirror_channel

channel = create_space_mirror_channel(
    name="cloud-mirror",
    session=session,
    collections=[SpaceMirrorCollection(id="accounts", space_name="app-mirror")],
    enabled_ids=lambda: enabled,                 # re-read every cycle; sync or async
    read_source=lambda cid, ctx: load(cid),
    doc_path=lambda space_id, node_id: f"spaces/{space_id}/objects/mirror/{node_id}",
)
```

Schedule it with `ChannelScheduler` (exported from `starfish_replica.space` as
`ReplicaManager`, matching the TS subpath's naming).

Three differences from TypeScript:

- **Write-only: there is no `read_space_mirror` yet.** This is a gap, not a
  design position. A reader needs invite/link-cap resolution and per-node
  keyrings (`get_node_access` tiers 1 and 3) that a *writer* never exercises,
  and which the Python `starfish_spaces` covers less completely than the
  TypeScript one. Read mirrored content with the TypeScript reader, or
  against the node documents directly, until it lands.
- **`SpacePort` owns the CAS push.** TypeScript's `NodeAccessHandle.push()`
  does pull→decrypt→mutate→encrypt→push itself; the Python
  `NodeAccessHandle` is a plain dataclass, so the port implements that over
  `starfish_spaces.cas_retry.run_cas`. (Python's `KeyringEncryptor` methods
  are synchronous.)
- **The port flattens the object tree.** Python's
  `starfish_spaces.read_object_tree` returns a *nested* tree, while TS's
  identically-named `readObjectTree` returns a *flat* list. Flattening keeps
  both planners equivalent — otherwise a non-root node would be invisible and
  get duplicated.
