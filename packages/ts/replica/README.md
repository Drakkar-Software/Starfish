# @drakkar.software/starfish-replica

Replication extension for [Starfish](https://github.com/Drakkar-Software/starfish). Lets you run
multiple Starfish servers that stay in sync: a **primary** holds the source of truth; **replicas**
pull from it and serve reads locally.

Shipped as a `ServerPlugin` — it owns its own config (the `remote` field is no longer part of the
core `CollectionConfig`).

## Install

```bash
pnpm add @drakkar.software/starfish-replica
```

## Usage

```ts
import { createSyncRouter } from "@drakkar.software/starfish-server"
import { createReplicaServerPlugin } from "@drakkar.software/starfish-replica"

const replica = createReplicaServerPlugin({
  store,
  syncConfig: config,
  collections: {
    // keyed by root collection name
    posts: {
      url: "https://primary.example.com/v1",
      pullPath: "/pull/posts/featured",
      intervalMs: 60_000,
      headers: { Authorization: "Bearer <replica-token>" },
      writeMode: "pull_only",        // clients can't push to this replica
      syncTriggers: ["scheduled"],   // or ["on_pull"]
    },
  },
})

const router = createSyncRouter({
  store,
  config,
  roleResolver,
  plugins: [replica /*, ...other plugins */],
})

replica.manager.start() // begin scheduled / initial syncs
```

Register `replica.shutdown` via the server's graceful shutdown (it stops the sync timers) — passing
the plugin in `plugins` to `createGracefulShutdown` handles this automatically.

## Write modes

| Mode | Client reads | Client writes | Syncs from primary |
| --- | --- | --- | --- |
| `pull_only` | ✓ | rejected (405) | ✓ replace |
| `push_through` | ✓ | forwarded to primary | ✓ replace |
| `bidirectional` | ✓ | stored locally | ✓ merge (remote-wins) |
| `push_only` | rejected (405) | stored locally | — |

`push_through` and `bidirectional` require `pushPath`.

## Authenticated replicas (`createReplicaAuth`)

When the primary requires cap-cert + Ed25519 request signing, build a signing
`fetch` wrapper with `createReplicaAuth` and inject it into the manager via
`fetchFn`. It signs every outgoing pull/push request and attaches the cap +
signature headers:

```ts
import { createReplicaAuth, ReplicaManager } from "@drakkar.software/starfish-replica"

const auth = await createReplicaAuth({ passphrase: PLATFORM_PASSPHRASE })
// Optional: cross-check the derived identity before trusting it.
if (auth.userId !== expectedUserId) throw new Error("identity mismatch")

const manager = new ReplicaManager(store, collections, { fetchFn: auth.fetch })
```

Per request it bootstraps (once) a self-signed device cap-cert from the
passphrase — or accepts a pre-bootstrapped `credentials: DeviceCredentials` — then
attaches:

| Header | Value |
| --- | --- |
| `Authorization` | `Cap ` + base64(stableStringify(cap-cert)) |
| `X-Starfish-Sig` | base64 Ed25519 signature over the canonical request bytes |
| `X-Starfish-Ts` | Unix milliseconds |
| `X-Starfish-Nonce` | base64 16-byte random nonce |

The cap-cert has a finite TTL (30 days by default). `createReplicaAuth` re-mints
it transparently when it nears expiry (`refreshMarginSec`, default one day) so a
long-uptime replica never 401-storms — the signing key and userId are preserved
across refreshes. `scope` defaults to `scopes.rootAll()`; pass a narrower
`ScopePreset` to restrict the cap.

See `docs/ts/replica/01-overview.md` for the full guide.

## A second data path: mirroring into a Starfish space (`./space`)

Everything above replicates a primary→replica-*server* HTTP pull into a local
`starfish-server` `ObjectStore`. This subpath drives an entirely different
kind of channel: mirroring a local data source (a mobile app's own store, a
node's local state) into per-collection nodes of one or more Starfish
spaces, encrypted under each space's own keyring.

The `ReplicaManager` exported from `./space` is a DIFFERENT class than the
root `.` entry's `ReplicaManager` — this one is pure scheduler (no HTTP back-
compat constructor), so importing it never pulls in `starfish-server`; safe
to bundle into a mobile or browser client.

```bash
pnpm add @drakkar.software/starfish-replica @drakkar.software/starfish-spaces
```

```ts
import { createSpaceMirrorChannel, ReplicaManager } from "@drakkar.software/starfish-replica/space"

const channel = createSpaceMirrorChannel({
  name: "cloud-mirror",
  session, // a starfish-spaces Session
  collections: [
    { id: "user-accounts", spaceName: "app-mirror" },
    { id: "user-settings", spaceName: "app-mirror-private" },
  ],
  enabledIds: () => currentlyEnabledCollectionIds(), // read fresh every sync
  readSource: (id) => readLocalCollection(id),
  docPath: (spaceId, nodeId) => `spaces/${spaceId}/objects/mirror/${nodeId}`,
})

const manager = new ReplicaManager([
  { channel, schedule: { triggers: ["scheduled"], intervalMs: 5 * 60_000 } },
])
manager.start()

// ... later, read the most recent sync's result:
channel.result // { spaces, created, written, skipped, cleared }
```

Read side (session-less, for a third party holding a read-only member cap
into the space — e.g. `starfish-spaces`' `inviteToSpace`):

```ts
import { readSpaceMirror } from "@drakkar.software/starfish-replica/space"

const collections = await readSpaceMirror({
  rendezvous: { baseUrl, namespace },
  spaceId,
  cap, // the minted member cap
  devEdPrivHex,
  devKemPrivHex,
  isKnownCollection: (type) => KNOWN_IDS.has(type),
  docPath: (spaceId, nodeId) => `spaces/${spaceId}/objects/mirror/${nodeId}`,
})
```

Notes:

- `changeDetection` defaults to `"none"` — every enabled collection is
  written unconditionally every cycle, matching a hand-rolled writer's usual
  behavior. Opt into `"source-hash"` only when this channel is the SOLE
  writer of a node; a second writer (e.g. a mobile device AND a node both
  writing the same mirror) would silently diverge from what a hash-skip
  assumes is already there.
- `ReplicaCallContext.callKind` (`"replicator"` vs `"classic"`) is threaded
  into `readSource` unchanged, so one shared data-access function can serve
  both a scheduler-driven sync and a direct app call without the channel or
  manager needing to know why it was invoked.
- `@drakkar.software/starfish-spaces`, `starfish-client`, and
  `starfish-keyring` are optional peer dependencies — only importing
  `@drakkar.software/starfish-replica/space` pulls them in; the root `.`
  entry (and `HttpReplicaChannel`) never does.
