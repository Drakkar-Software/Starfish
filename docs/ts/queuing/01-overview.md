# Queuing (Change Events)

`starfish-queuing` is the change-event extension. After every successful push,
the server hands each registered plugin a `WriteEvent`; the queuing plugin
publishes a lightweight JSON message to a message queue so downstream services
can react to data changes without polling.

It lives in its own package — `@drakkar.software/starfish-queuing` (TS) /
`starfish-queuing` (Python) — and hooks into the server through the
`ServerPlugin.afterWrite` contract. `starfish-server` has no dependency on it;
apps wire both packages together.

## How it works

1. Build a queuing plugin with a `Queue` and a per-collection config map:
   `createQueuingServerPlugin({ queue, collections })`.
2. Pass it to `createSyncRouter` via `SyncRouterOptions.plugins`.
3. On every successful push (HTTP 200) to a configured collection, the plugin
   publishes a JSON payload to the configured topic.

Queue errors never surface to clients — they are logged and the push response is
returned normally. The collection only publishes if it appears in the plugin's
`collections` map.

## QueueConfig

```ts
interface QueueConfig {
  topic?: string            // Topic / NATS subject. Defaults to the collection name.
  includeParams: boolean    // Include resolved path params in the payload (default: false)
  includeBody?: boolean     // Include full document data in the payload (default: false, JSON only)
  includeIdentity?: boolean // Include the writer's authenticated userId (default: false)
}
```

## Server setup

```ts
import { createSyncRouter, createGracefulShutdown } from "@drakkar.software/starfish-server"
import { createQueuingServerPlugin, CustomQueue } from "@drakkar.software/starfish-queuing"

const queue = new CustomQueue({
  onPublish: async (subject, payload) => {
    await natsClient.publish(subject, payload)
  },
})

const queuing = createQueuingServerPlugin({
  queue,
  collections: {
    // Publish to topic "posts" (= collection name) without path params
    posts: { includeParams: false },
    // Custom topic + include resolved path params in the payload
    comments: { topic: "data.comments.changed", includeParams: true },
  },
})

const sync = createSyncRouter({ store, config, roleResolver, plugins: [queuing] })

// The plugin's shutdown hook closes the queue when plugins are passed here:
const handle = createGracefulShutdown({ plugins: [queuing] })

const app = new Hono()
app.route("/v1", sync)
```

## Event payload

Every event is a UTF-8 JSON object conforming to the exported `QueueMessage` type:

```ts
import type { QueueMessage } from "@drakkar.software/starfish-queuing"
```

Base shape (always present):

```json
{ "collection": "posts", "hash": "abc123...", "timestamp": 1712345678000 }
```

With `includeParams: true`, resolved path parameters are added under `params`;
with `includeBody: true`, the pushed `data` object is added under `body` (JSON
collections only — never for binary collections); with `includeIdentity: true`,
the authenticated writer's cap-bound userId (`WriteEvent.identity`) is added under
`identity`. `includeIdentity` is **off by default**: it exposes *who* wrote each
document to the broker — metadata the server otherwise never emits — so it is
strictly per-collection opt-in.

> **Note:** `body` is captured from the raw request before server-side
> sanitization (which removes prototype-pollution keys such as `__proto__`), so
> it is not guaranteed byte-for-byte identical to what was written to storage.

## Queue interface and built-in implementations

```ts
interface Queue {
  connect?(): Promise<void>   // Optional
  publish(subject: string, payload: Uint8Array): Promise<void>
  close?(): Promise<void>     // Optional: called by the plugin's shutdown hook
}
```

- **`MemoryQueue`** — accumulates published messages in `.messages` (testing).
- **`CustomQueue`** — routes events to a sync/async `onPublish` callback (any bus:
  Redis, SQS, Kafka, WebSockets, …).
- **`NatsQueue`** (Python only) — NATS backend; `pip install "starfish-queuing[nats]"`.

Any object satisfying `Queue` works — e.g. a `RedisQueue implements Queue`.

## Append-only collections (no storage)

Set `appendOnly: { type: "by_timestamp", persist: false }` on a collection to emit a change event
without writing anything to storage. This `persist` flag stays a **server**
config field; it produces a `WriteEvent` that the queuing plugin (or any
`afterWrite` plugin) consumes. The server warns at startup if a `persist: false`
collection is configured but no `afterWrite` plugin is registered.

```ts
// server config
{ name: "events", storagePath: "events/{eventId}", readRoles: ["public"],
  writeRoles: ["admin"], encryption: "none", maxBodyBytes: 65536,
  appendOnly: { type: "by_timestamp", persist: false } }

// queuing plugin
createQueuingServerPlugin({
  queue,
  collections: { events: { topic: "analytics.events", includeParams: true } },
})
```

| | Normal | `appendOnly` + `persist: false` |
|---|---|---|
| Storage write | Yes | No |
| Hash conflict check | Yes (`baseHash` validated) | No (any `baseHash` accepted) |
| Pull response | Returns stored data | Returns empty (`{}`) |
| Queue event | If collection configured in the plugin | If collection configured in the plugin |

`appendOnly` cannot be used with binary collections. **Client usage:** use
`push()` directly — never `update()` (pull always returns empty for
`persist: false`).

## Python

The Python API mirrors the TypeScript one.

```python
from starfish_server.router.route_builder import create_sync_router, SyncRouterOptions
from starfish_server.lifecycle import GracefulShutdown, GracefulShutdownOptions
from starfish_queuing import create_queuing_server_plugin, CustomQueue, QueueConfig

queue = CustomQueue(on_publish=lambda s, p: nats_client.publish(s, p))

queuing = create_queuing_server_plugin(
    queue=queue,
    collections={
        "posts": QueueConfig(include_params=False),
        "comments": QueueConfig(topic="data.comments.changed", include_params=True),
    },
)

router = create_sync_router(
    SyncRouterOptions(store=store, config=config, role_resolver=role_resolver, plugins=[queuing]),
)

# The plugin's shutdown hook closes the queue:
shutdown = GracefulShutdown(GracefulShutdownOptions(plugins=[queuing]))
```

### NatsQueue (Python)

```python
from starfish_queuing.nats import NatsQueue, NatsQueueOptions

queue = NatsQueue(NatsQueueOptions(servers="nats://localhost:4222"))
# await queue.connect() / await queue.close() — or let the plugin's shutdown hook close it.
```

### Custom backend (Python)

```python
from starfish_queuing.base import AbstractQueue

class SQSQueue(AbstractQueue):
    def __init__(self, client, queue_url: str) -> None:
        self._client, self._queue_url = client, queue_url

    async def publish(self, subject: str, payload: bytes) -> None:
        await self._client.send_message(
            QueueUrl=self._queue_url,
            MessageBody=payload.decode(),
            MessageAttributes={"subject": {"StringValue": subject, "DataType": "String"}},
        )
```
