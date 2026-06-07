# starfish-outbox

A durable, per-identity **offline write-queue** — the client-side complement to the
server-side `queuing` extension.

Generic over the queued item: you own what an item is, supply its dedup `id`, and a
`send` that performs the real write. The queue handles persistence (write-through to a
`LocalCache`), dedup-by-id, single-shot claim (no double-send), attempt counting with
auto-retry-then-fail, crash-safe recovery of stuck `sending` entries, and subscriptions.
`drain_outbox` is connectivity-agnostic — you trigger it on whatever reconnect signal you have.

## Install

```sh
pip install starfish-outbox
```

## Usage

```python
from starfish_outbox import OutboxQueue, drain_outbox

queue: OutboxQueue = OutboxQueue(local_cache)  # local_cache: async get_item / set_item / remove_item
await queue.hydrate(f"outbox.{user_id}")

# Enqueue a write while offline (the id is yours to thread into the eventual write):
await queue.enqueue(write_id, {"path": path, "body": body})

# Drain on reconnect:
async def send(entry):
    await client.push(entry.item["path"], entry.item["body"], base_hash_for(entry.item["path"]))

await drain_outbox(queue, send, max_attempts=5)
```

Mutating methods (`enqueue` / `claim` / `remove` / `retry` / …) are `async` because each
writes through to the cache; `get` / `pending` / `subscribe` are synchronous. JSON-compatible
on disk with the TypeScript `@drakkar.software/starfish-outbox`.
