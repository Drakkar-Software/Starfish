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

See `docs/ts/replica/01-overview.md` for the full guide.
