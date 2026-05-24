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

Unlike the client-side cap extensions, `starfish-replica` depends on
`starfish-server` — the `ReplicaManager` writes pulled data through the server's
`push()` (hash-based conflict detection) into the `ObjectStore`.

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
