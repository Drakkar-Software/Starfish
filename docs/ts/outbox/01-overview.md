# @drakkar.software/starfish-outbox

A durable, per-identity **offline write-queue** — the client-side complement to the
server-side `queuing` extension.

Generic over the queued item `<T>`: you own what an
item is, supply its dedup `id`, and a `send` that performs the real write. The queue
handles persistence (write-through to a `LocalCache`), dedup-by-id, single-shot
claim (no double-send), attempt counting with auto-retry-then-fail, crash-safe
recovery of stuck `sending` entries, and subscriptions. `drainOutbox` is
connectivity-agnostic — you trigger it on whatever reconnect signal you have (e.g.
the client's `createMobileLifecycle` `NetInfoModule`, or `window`'s `online` event).

## Install

```sh
pnpm add @drakkar.software/starfish-outbox
```

## Usage

```ts
import { createOutboxQueue, drainOutbox } from "@drakkar.software/starfish-outbox"

const queue = createOutboxQueue<{ path: string; body: unknown }>(localCache)
await queue.hydrate(`outbox.${userId}`)

// Enqueue a write while offline (the id is yours to thread into the eventual write):
queue.enqueue(writeId, { path, body })

// Drain on reconnect:
await drainOutbox(queue, async (entry) => {
  await client.push(entry.item.path, entry.item.body, baseHashFor(entry.item.path))
}, { maxAttempts: 5 })
```

Python: `starfish-outbox` mirrors this (`OutboxQueue`, `drain_outbox`); mutators are
`async` there because each writes through to the cache.
