# Audit Logging

The audit logger records every pull and push that the server handles — including failed requests — with enough context to answer: who did what, to which collection, when, and whether it succeeded.

---

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

---

## Built-in loggers

### Console logger

Writes a single line per event. Useful during development.

```ts
import { createConsoleAuditLogger, createSyncRouter } from "@drakkar.software/starfish-server"

const syncRouter = createSyncRouter({
  store,
  config,
  roleResolver,
  auditLogger: createConsoleAuditLogger(),
})
```

Output format:

```
[Starfish:AUDIT] PULL settings by alice → OK (200)
[Starfish:AUDIT] PUSH notes by bob → FAIL (403)
```

### Callback logger

Delegates to any sync or async function. Use this to write to a database, send to a log
aggregation service, or enqueue for downstream processing.

```ts
import { createCallbackAuditLogger } from "@drakkar.software/starfish-server"

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

### No-op logger

Discards all entries. This is the default when `auditLogger` is not set in `createSyncRouter`.

```ts
import { createNoopAuditLogger } from "@drakkar.software/starfish-server"
// Equivalent to omitting the audit option entirely
```

---

## Python

> **Note:** Audit logging is not yet implemented in the Python server. The `SyncRouterOptions` dataclass does not have an `audit_logger` field. Use application-level middleware or a logging framework to capture request events in Python deployments.

---

## Custom logger

Implement the interface directly to send to any backend.

### TypeScript

```ts
import type { AuditLogger, AuditEntry } from "@drakkar.software/starfish-server"

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
from starfish_server.audit import AuditLogger, AuditEntry

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

---

## What is and isn't logged

**Logged:** Every request that reaches the router, regardless of outcome — including 403 (unauthorized), 409 (conflict), 413 (body too large), and 415 (wrong MIME type).

**Not logged:** Requests that fail before the router (e.g. malformed paths, CORS pre-flight) and internal background operations (replica sync, graceful shutdown).

---

## Related

- [Queue](queue.md) — queue events are a separate stream and are not duplicated in the audit log
- [Logging](../client/16-logging-observability.md) — structured sync logging on the client side
