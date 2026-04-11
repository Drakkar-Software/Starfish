# Queue (Change Events)

After every successful push, Starfish can publish a lightweight change event to a message queue. This lets downstream services react to data changes without polling.

## How it works

1. A `Queue` instance is wired into `createSyncRouter` via `SyncRouterOptions.queue`.
2. Each collection opts in individually via the `queue` field in its `CollectionConfig`.
3. On every successful push (HTTP 200), the server publishes a JSON payload to the configured topic.

Queue errors never surface to clients — they are logged to `console.error` and the push response is returned normally.

## QueueConfig

```ts
interface QueueConfig {
  topic?: string        // Topic / NATS subject to publish to. Defaults to the collection name.
  includeParams: boolean  // Include resolved path params in the payload (default: false)
  includeBody?: boolean   // Include full document data in the payload (default: false, JSON only)
}
```

### Shorthand

Pass `true` to use defaults (topic = collection name, `includeParams: false`, `includeBody: false`):

```json
{ "queue": true }
```

Pass `false` or omit `queue` entirely to disable queue events for that collection.

## Collection config

```ts
const config = parseConfigJson(JSON.stringify({
  version: 1,
  collections: [
    {
      name: "posts",
      storagePath: "posts/{postId}",
      readRoles: ["public"],
      writeRoles: ["admin"],
      encryption: "none",
      maxBodyBytes: 65536,
      // Publish to topic "posts" (= collection name) without path params
      queue: true,
    },
    {
      name: "comments",
      storagePath: "posts/{postId}/comments/{commentId}",
      readRoles: ["public"],
      writeRoles: ["user"],
      encryption: "none",
      maxBodyBytes: 16384,
      // Custom topic + include resolved path params in the payload
      queue: { topic: "data.comments.changed", includeParams: true },
    },
  ],
}))
```

## Event payload

Every event is a UTF-8 JSON object conforming to the exported `QueueMessage` type:

```ts
import type { QueueMessage } from "@drakkar.software/starfish-server"
```

The base shape (always present):

```json
{
  "collection": "posts",
  "hash": "abc123...",
  "timestamp": 1712345678000
}
```

When `includeParams: true`, the resolved path parameters are added:

```json
{
  "collection": "comments",
  "hash": "def456...",
  "timestamp": 1712345679000,
  "params": { "postId": "post-1", "commentId": "c-42" }
}
```

When `includeBody: true`, the full document data is added (JSON collections only):

```json
{
  "collection": "posts",
  "hash": "abc123...",
  "timestamp": 1712345678000,
  "body": { "title": "Hello world", "published": true }
}
```

`body` contains the `data` field from the push request body as sent by the client. It is never present for binary collections. Use it when consumers need the document content without making a follow-up pull request — for example, when indexing into a search engine or writing to an audit log.

> **Note:** `body` is captured from the raw request before server-side sanitization (which removes prototype-pollution keys such as `__proto__`). In practice the difference is negligible for normal payloads, but `body` is not guaranteed to be byte-for-byte identical to what was written to storage.

## Queue interface

```ts
interface Queue {
  connect?(): Promise<void>   // Optional: called during startup
  publish(subject: string, payload: Uint8Array): Promise<void>
  close?(): Promise<void>     // Optional: called during graceful shutdown
}
```

## Built-in implementations

### MemoryQueue (testing)

Accumulates all published messages in memory. Ideal for unit/integration tests.

```ts
import { MemoryQueue } from "@drakkar.software/starfish-server"

const queue = new MemoryQueue()

const router = createSyncRouter({ store, config, roleResolver, queue })

// After a push, inspect recorded events:
const [subject, payload] = queue.messages[0]
const event = JSON.parse(new TextDecoder().decode(payload))
console.log(event) // { collection: "posts", hash: "...", timestamp: ... }
```

### CustomQueue (callback)

Routes events to any callback — sync or async. Use this to integrate with any message bus (Redis, SQS, Kafka, WebSockets, etc.):

```ts
import { CustomQueue } from "@drakkar.software/starfish-server"

const queue = new CustomQueue({
  onPublish: async (subject, payload) => {
    const event = JSON.parse(new TextDecoder().decode(payload))
    await myBus.publish(subject, event)
  },
})
```

## Server setup

Wire the queue into `createSyncRouter` and manage its lifecycle through `createGracefulShutdown`:

```ts
import { createSyncRouter, CustomQueue, createGracefulShutdown } from "@drakkar.software/starfish-server"

const queue = new CustomQueue({
  onPublish: async (subject, payload) => {
    await natsClient.publish(subject, payload)
  },
})

const sync = createSyncRouter({ store, config, roleResolver, queue })

const handle = createGracefulShutdown({
  queue,
  onShutdown: async () => { /* close other resources */ },
})

const app = new Hono()
app.route("/v1", sync)
```

`createGracefulShutdown` calls `queue.connect()` on startup and `queue.close()` on SIGTERM/SIGINT if those methods exist.

## Implementing a custom Queue

Any object that satisfies the `Queue` interface works:

```ts
import type { Queue } from "@drakkar.software/starfish-server"

class RedisQueue implements Queue {
  constructor(private readonly redis: Redis) {}

  async publish(subject: string, payload: Uint8Array): Promise<void> {
    await this.redis.publish(subject, Buffer.from(payload))
  }
}
```

## Python

The Python server exposes the same abstraction under `starfish_server.queue`.

### Built-in implementations

| Class | Purpose |
|---|---|
| `MemoryQueue` | Testing — records all messages in `.messages` |
| `CustomQueue` | Callback-based — sync or async `on_publish` |
| `NatsQueue` | NATS backend (`pip install starfish-server[nats]`) |

### NatsQueue setup

```python
from contextlib import asynccontextmanager
from starfish_server.queue.nats import NatsQueue, NatsQueueOptions

queue = NatsQueue(NatsQueueOptions(servers="nats://localhost:4222"))

sync_router = create_sync_router(SyncRouterOptions(
    store=store,
    config=config,
    role_resolver=role_resolver,
    queue=queue,
))

@asynccontextmanager
async def lifespan(app):
    await queue.connect()
    yield
    await queue.close()

app = FastAPI(lifespan=lifespan)
app.include_router(sync_router, prefix="/v1")
```

### Collection config (Python)

```python
from starfish_server import CollectionConfig, QueueConfig

CollectionConfig(
    name="posts",
    storage_path="posts/{postId}",
    read_roles=["public"],
    write_roles=["admin"],
    encryption="none",
    max_body_bytes=65536,
    queue=True,  # topic = "posts", include_params = False, include_body = False
    # Or:
    # queue=QueueConfig(topic="data.posts.changed", include_params=True, include_body=True),
)
```

### Implementing a custom Queue (Python)

```python
from starfish_server.queue.base import AbstractQueue

class SQSQueue(AbstractQueue):
    def __init__(self, client, queue_url: str) -> None:
        self._client = client
        self._queue_url = queue_url

    async def publish(self, subject: str, payload: bytes) -> None:
        await self._client.send_message(
            QueueUrl=self._queue_url,
            MessageBody=payload.decode(),
            MessageAttributes={"subject": {"StringValue": subject, "DataType": "String"}},
        )
```
