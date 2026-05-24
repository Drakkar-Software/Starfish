# starfish-audit

`@drakkar.software/starfish-audit` (TS) / `starfish-audit` (Py) — audit logging
extension. Ready-made loggers that record every server access event (who did what,
to which collection, when, and whether it succeeded), including failed requests.

The `AuditEntry` / `AuditLogger` **contract** lives in `starfish-protocol` (so the
server can emit events and this package can supply loggers without a dependency
cycle); the **concrete loggers** ship here. Audit is server-side observability — it
registers no cap-cert validator and no server plugin.

## What it provides

- `createConsoleAuditLogger()` — one line per event (development).
- `createCallbackAuditLogger(cb)` — delegates to any sync/async function (DB, log aggregation, queue).
- `createNoopAuditLogger()` — discards entries (equivalent to omitting `auditLogger`).
- Re-exports the `AuditEntry` / `AuditLogger` types from `starfish-protocol`.

## AuditEntry fields

| Field | Type | Description |
|---|---|---|
| `timestamp` | `number` | Unix timestamp in milliseconds |
| `action` | `"pull" \| "push"` | Operation type |
| `collection` | `string` | Collection name from the config |
| `identity` | `string \| null` | Resolved identity, or `null` for anonymous |
| `documentKey` | `string` | Full storage key (includes resolved path params) |
| `success` | `boolean` | Whether the request returned a 2xx status |
| `statusCode` | `number` | HTTP response status code |
| `params` | `Record<string, string>` | Resolved URL parameters (e.g. `{ identity: "alice", groupId: "g1" }`) |

## Install

```sh
pnpm add @drakkar.software/starfish-server @drakkar.software/starfish-audit
```

## Server wiring

```ts
import { createSyncRouter } from "@drakkar.software/starfish-server"
import { createConsoleAuditLogger } from "@drakkar.software/starfish-audit"

const syncRouter = createSyncRouter({
  store,
  config,
  roleResolver,
  auditLogger: createConsoleAuditLogger(),
})
```

Console output format:

```
[Starfish:AUDIT] PULL settings by alice → OK (200)
[Starfish:AUDIT] PUSH notes by bob → FAIL (403)
```

### Callback logger

```ts
import { createCallbackAuditLogger } from "@drakkar.software/starfish-audit"

const syncRouter = createSyncRouter({
  store,
  config,
  roleResolver,
  auditLogger: createCallbackAuditLogger(async (entry) => {
    await db.insert("audit_log", {
      ts:         entry.timestamp,
      action:     entry.action,
      collection: entry.collection,
      identity:   entry.identity,
      doc_key:    entry.documentKey,
      ok:         entry.success,
      status:     entry.statusCode,
    })
  }),
})
```

## Custom logger

Implement the `AuditLogger` interface directly to send to any backend.

### TypeScript

```ts
import type { AuditLogger, AuditEntry } from "@drakkar.software/starfish-audit"

class DatadogAuditLogger implements AuditLogger {
  record(entry: AuditEntry): void {
    datadogLogs.logger.info("starfish.audit", {
      action:     entry.action,
      collection: entry.collection,
      identity:   entry.identity,
      success:    entry.success,
      status:     entry.statusCode,
    })
  }
}
```

### Python

```python
from starfish_audit import AuditLogger, AuditEntry

class DatadogAuditLogger(AuditLogger):
    async def record(self, entry: AuditEntry) -> None:
        datadog_logger.info("starfish.audit", extra={
            "action":     entry.action,
            "collection": entry.collection,
            "identity":   entry.identity,
            "success":    entry.success,
            "status":     entry.status_code,
        })
```

## What is and isn't logged

**Logged:** Every request that reaches the router, regardless of outcome — including 403 (unauthorized), 409 (conflict), 413 (body too large), and 415 (wrong MIME type).

**Not logged:** Requests that fail before the router (e.g. malformed paths, CORS pre-flight) and internal background operations (replica sync, graceful shutdown).

> **Language parity:** auth-layer **denials** (401/403) are recorded on **both pull and push** in **both** languages. On the **success** path the languages still differ: the TypeScript server emits on both pull and push, while the Python server currently emits on **push** only.

## Related

- [Queuing](../queuing/01-overview.md) — queue events are a separate stream and are not duplicated in the audit log
- [Logging](../client/16-logging-observability.md) — structured sync logging on the client side
