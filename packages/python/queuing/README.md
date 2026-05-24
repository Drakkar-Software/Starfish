# starfish-queuing

Change-event queuing extension for Starfish (Python). After a successful push,
the server hands each registered plugin a `WriteEvent`; this plugin publishes a
`QueueMessage` to a configured transport (`MemoryQueue`, `CustomQueue`,
`NatsQueue`, or your own `AbstractQueue`).

## Install

```sh
pip install starfish-server starfish-queuing
# with NATS support:
pip install "starfish-queuing[nats]"
```

## Usage

```python
from starfish_server import create_sync_router, SyncRouterOptions
from starfish_queuing import create_queuing_server_plugin, MemoryQueue, QueueConfig

queue = MemoryQueue()

plugin = create_queuing_server_plugin(
    queue=queue,
    collections={
        "events": QueueConfig(topic="events", include_params=True, include_body=True),
    },
)

router = create_sync_router(
    SyncRouterOptions(
        config=config,
        store=store,
        # …
        plugins=[plugin],
    )
)
```

The plugin publishes only for collections present in its `collections` map.
`topic` defaults to the collection name — an unset *or empty-string* topic falls
back to it (an empty broker subject is a footgun). `shutdown()` closes the queue
when the server's graceful-shutdown handler is given the plugin list.

See `docs/ts/queuing/` for the full guide (the TypeScript and Python APIs mirror
each other).
