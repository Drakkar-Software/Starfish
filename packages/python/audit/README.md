> ⚠️ **Deprecated.** The Python implementation of Starfish is no longer maintained in
> parity with the TypeScript packages and will be **removed in a future release**.
> Use the TypeScript `@drakkar.software/starfish-*` packages instead.

# starfish-audit

Starfish audit logging extension for Python — ready-made audit loggers for
recording the server's pull/push access events. The `AuditEntry` / `AuditLogger`
contract lives in `starfish-protocol`; this package ships the concrete loggers.

## Install

```sh
pip install starfish-server starfish-audit
```

## Usage

Pass a logger to the sync router via `audit_logger`:

```python
from starfish_server.router.route_builder import create_sync_router, SyncRouterOptions
from starfish_audit import ConsoleAuditLogger

router = create_sync_router(
    SyncRouterOptions(
        store=store,
        config=config,
        role_resolver=role_resolver,
        audit_logger=ConsoleAuditLogger(),
    ),
)
```

Write your own sink with `CallbackAuditLogger` (sync or async callback):

```python
from starfish_audit import CallbackAuditLogger, AuditEntry

async def _record(entry: AuditEntry) -> None:
    await db.audit.insert(entry)

audit_logger = CallbackAuditLogger(_record)
```

`NoopAuditLogger` discards entries.

The server **awaits** `record()` for each request, so the entry is durable before
the response is returned. Keep the sink fast and resilient: a slow logger adds
request latency and a raising one surfaces as a request error.

> Audit logging is server-side observability — this package depends only on
> `starfish-protocol` and registers no cap-cert validator. Note: the Python
> server currently emits audit entries on **push** operations (the TypeScript
> server emits on both pull and push).

See `docs/python/audit/` (and the TypeScript counterpart in `docs/ts/audit/`) for the full guide.
