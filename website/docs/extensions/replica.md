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
  collections: [
    { id: "user-accounts", spaceName: "app-mirror" },                  // tier defaults to "private"
    { id: "public-profile", spaceName: "app-mirror", tier: "public" },
  ],
  enabledIds: () => currentlyEnabledCollectionIds(),
  readSource: (id, ctx) => readLocalCollection(id),
  docPath: (collectionId, spaceId, nodeId) =>
    `spaces/${spaceId}/objects/mirror/${nodeId}`,
  title: (collectionId) => `Mirror: ${collectionId}`,   // optional; defaults to the id
})

const manager = new ReplicaManager([
  { channel, schedule: { triggers: ["scheduled"], intervalMs: 5 * 60_000 } },
])
manager.start()

channel.result  // { spaces, created, written, skipped, cleared, failed } after the last sync
```

`ReplicaManager` here is imported from `./space`, not the root `.` entry — see
the note above: it is `ChannelScheduler` directly, so this whole example never
touches `starfish-server`.

`SpaceMirrorChannel` finds-or-creates one space per distinct `spaceName` in
`collections`, finds-or-creates one node per collection id, and CAS-writes
`readSource`'s result into it every cycle — `changeDetection` defaults to
`"none"` (always write) since a source-hash skip is only sound when this
channel is the *sole* writer of a node.

#### Storage tiers

Each collection carries a `tier` selecting the access axes its node is created
with *and* written through — a single closed enum rather than a raw
`{ access, enc }` pair, because the server rejects `access: "public"` with
`enc: true` and an enum makes that combination unrepresentable instead of a
failure discovered late, at `createNode`.

| `tier` | resolves to | meaning |
| --- | --- | --- |
| `"private"` (default) | the channel-wide `nodeEnc`, itself `{ access: "space", enc: true }` unless you overrode it | readable only by space members, sealed under the space's own keyring |
| `"public"` | `{ access: "public", enc: false }`, always, ignoring `nodeEnc` | world-readable plaintext at its storage URL |

Writing `tier: "private"` out is exactly equivalent to omitting it: both
resolve to `nodeEnc`, so spelling out the default never costs you an override.
Only `"public"` overrides `nodeEnc`.

Flipping a collection between tiers is safe, **including across a restart**.
The channel compares the node's *stored* `access`/`enc` (recorded in the space's
object index, so they survive the process) against the tier it is configured
for now; when they differ it clears the node under the **stored** axes before
writing under the new ones. Skipping that on a `public` → `private` flip would
leave the previously published plaintext sitting at a world-readable URL
indefinitely, which is the whole reason the clear exists.

Once the new content is written, the node's *stored* axes are **patched** to the
new tier, through `SpacePort.setNodeAccess` / `set_node_access`. The order —
clear old path, write new path, patch stored axes — matters: patching before
the write would leave the index claiming a tier the stored content does not
match if the write then failed.

That patch is not bookkeeping. The object index is projected into a
**world-readable** index of every `access: "public"` node's `id`, `title` and
`type`. A node left recorded as public therefore keeps being advertised to
anonymous callers even after its content has been cleared, which directly
contradicts the setting the user just changed. The patch is also what makes a
flip self-limiting: without it the stored axes read as the old tier on every
subsequent cycle, so the clear re-fires forever and a
`changeDetection: "source-hash"` collection that flipped once can never skip
again. The patch normalizes exactly the way node creation does (no `access` for
`"space"`, no `enc` when false), so a patched node is indistinguishable from one
born at that tier, and a patch that itself fails is isolated like any other
per-collection failure — the collection lands in `result.failed` and its error
in the raised group, without aborting the cycle.

The `changeDetection: "source-hash"` fingerprint is keyed by node id *and* tier
for the same reason the migrating write must happen at all — a tier change does
not alter what `readSource` returns, so a node-id-keyed hash would skip the one
write that migrates the node.

`title` is an optional `(collectionId) => string` used only when a node is
first created; it defaults to the collection id.

The read side, `readSpaceMirror`, is session-less: given a member cap for the
space (e.g. minted via `inviteToSpace`) plus the grant holder's own ephemeral
keys, it pulls and decrypts every node it recognizes. No `.` (`ReplicaManager`)
type or plugin machinery is involved on this side — it's a standalone function.

It pulls the space keyring **lazily** — only once a node's document actually
comes back carrying `_encrypted`. A space whose every collection is written at
`tier: "public"` never mints a keyring at all (nothing in it was ever
encrypted), and this reader reads such a space in full without one. A space that
does contain an encrypted node but has no keyring still fails with the same
"this space has no keyring yet" error.

#### Reading the public tier

`readPublicSpaceMirror` is the read side of `tier: "public"`, and needs **no
grant, no cap and no keyring** — it builds an anonymous client, the same one
`readObjectDirectory` uses. That is the point of the tier: anyone holding the
space id reads what its owner chose to publish, with no invite in between.

```ts
import { readPublicSpaceMirror } from "@drakkar.software/starfish-replica/space"

const published = await readPublicSpaceMirror({
  rendezvous: { baseUrl, namespace },
  spaceId,
  // Optional: ids the caller already has (from a share link, say). Omit them
  // to enumerate the public object directory instead.
  nodes: [{ id: nodeId, type: "public-strategy" }],
  isKnownCollection: (type) => KNOWN_IDS.has(type), // optional; default: all
  docPath: (collectionId, spaceId, nodeId) => `spaces/${spaceId}/objects/pub/${nodeId}`,
})
```

It cannot enumerate the space the way `readSpaceMirror` does: the object index
is `space:member`, so an anonymous caller may not list a space's nodes. So it
takes either explicit `nodes` (`{ id, type }`) or, when they're omitted, pulls
the world-readable public object directory at `_index/objects/{shard}`
(`directoryShard`, default `"public"`) and reads every entry it lists for
`spaceId` — a server-maintained projection of `objindex` writes that by
construction only ever advertises `access: "public"` nodes. `docPath` is the
same widened `(collectionId, spaceId, nodeId)` template the writer and
`readSpaceMirror` take, so one literal serves all three, and the result is keyed
the same way: collection id (the node's `type`) to plaintext document.

A node whose document unexpectedly carries `_encrypted` is **omitted** from the
result rather than returned — handing back the sealed envelope would give the
caller ciphertext it would go on to treat as data. Omitted rather than thrown on
because the state is reachable with nothing broken: a `public` -> `private` flip
writes the encrypted content *before* patching the node's stored access, so for
that window the directory still advertises a node whose content is already
sealed, and one such node must not cost every other published collection its
read. A failed *directory* pull does throw, unlike `readObjectDirectory`'s
empty-list fallback: "the server is unreachable" must not be indistinguishable
from "this space publishes nothing".

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
    collections=[
        SpaceMirrorCollection(id="accounts", space_name="app-mirror"),   # tier defaults to "private"
        SpaceMirrorCollection(id="profile", space_name="app-mirror", tier="public"),
    ],
    enabled_ids=lambda: enabled,                 # re-read every cycle; sync or async
    read_source=lambda cid, ctx: load(cid),
    doc_path=lambda cid, space_id, node_id: f"spaces/{space_id}/objects/mirror/{node_id}",
    title=lambda cid: f"Mirror: {cid}",          # optional; defaults to the id
)
```

`tier` and `title` behave exactly as described above, including the stored-axes
flip detection and the post-write patch back into the object index.

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
