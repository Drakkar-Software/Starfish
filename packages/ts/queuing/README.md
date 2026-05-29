# @drakkar.software/starfish-queuing

Change-event queuing extension for Starfish. After a successful push, the
server hands each registered plugin a `WriteEvent`; this plugin publishes a
`QueueMessage` to a configured transport (in-process `MemoryQueue`, callback
`CustomQueue`, or your own `Queue` implementation).

## Install

```sh
pnpm add @drakkar.software/starfish-server @drakkar.software/starfish-queuing
```

## Usage

```ts
import { createSyncRouter } from "@drakkar.software/starfish-server"
import { createQueuingServerPlugin, MemoryQueue } from "@drakkar.software/starfish-queuing"

const queue = new MemoryQueue()

const router = createSyncRouter({
  config,
  store,
  // …
  plugins: [
    createQueuingServerPlugin({
      queue,
      collections: {
        events: { topic: "events", includeParams: true, includeBody: true },
      },
    }),
  ],
})
```

The plugin publishes only for collections present in its `collections` map.
`topic` defaults to the collection name — an unset *or empty-string* topic falls
back to it (an empty broker subject is a footgun). Per-collection flags select what
the message carries: `includeParams` (route params), `includeBody` (the pushed
`data`, JSON only), and `includeIdentity` (the authenticated writer's userId). All
default off; `includeIdentity` in particular exposes *who* wrote off-box, so it is
strictly opt-in. `shutdown()` closes the queue when the server's graceful-shutdown
handler is given the plugin list.

See `docs/ts/queuing/` for the full guide.
