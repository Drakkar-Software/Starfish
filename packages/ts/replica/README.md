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
