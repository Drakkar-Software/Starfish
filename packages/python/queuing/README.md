> ⚠️ **Deprecated.** The Python implementation of Starfish is no longer maintained in
> parity with the TypeScript packages and will be **removed in a future release**.
> Use the TypeScript `@drakkar.software/starfish-*` packages instead.

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
back to it (an empty broker subject is a footgun). Per-collection flags select what
the message carries: `include_params` (route params), `include_body` (the pushed
`data`, JSON only), and `include_identity` (the authenticated writer's userId). All
default off; `include_identity` in particular exposes *who* wrote off-box, so it is
strictly opt-in. `shutdown()` closes the queue when the server's graceful-shutdown
handler is given the plugin list.

`subject_param` appends a route path-param to the subject — a per-resource subject
`<topic>.<value>` (e.g. `posts.changed.<postId>`) so a broker/consumer can filter by
resource (NATS `<topic>.>`) without parsing the body. The value is read from the
write event's params (independent of `include_params`) and re-validated against
`subject_id_pattern` (default `DEFAULT_SAFE_ID` = `^[a-zA-Z0-9_-]+$`); a missing,
non-string, or metacharacter-bearing id falls back to the base subject, so the broker
never sees a `.`/`*`/`>` token:

```python
QueueConfig(topic="posts.changed", subject_param="postId")  # → posts.changed.<postId>
```

See `docs/ts/queuing/` for the full guide (the TypeScript and Python APIs mirror
each other).
