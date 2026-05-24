# @drakkar.software/starfish-audit

Starfish audit logging extension — ready-made audit loggers for recording the
server's pull/push access events. The `AuditEntry` / `AuditLogger` contract lives
in `@drakkar.software/starfish-protocol`; this package ships the concrete loggers.

## Install

```sh
pnpm add @drakkar.software/starfish-server @drakkar.software/starfish-audit
```

## Usage

Pass a logger to `createSyncRouter` via `auditLogger`:

```ts
import { createSyncRouter } from "@drakkar.software/starfish-server"
import { createConsoleAuditLogger } from "@drakkar.software/starfish-audit"

const router = createSyncRouter({
  store,
  config,
  roleResolver,
  auditLogger: createConsoleAuditLogger(),
})
```

Write your own sink with `createCallbackAuditLogger` (e.g. push to a database or
metrics pipeline):

```ts
import { createCallbackAuditLogger, type AuditEntry } from "@drakkar.software/starfish-audit"

const auditLogger = createCallbackAuditLogger(async (entry: AuditEntry) => {
  await db.audit.insert(entry)
})
```

`createNoopAuditLogger` discards entries (useful as a default).

The server **awaits** `record()` for each request, so the entry is durable before
the response is returned. Keep the sink fast and resilient: a slow logger adds
request latency and a throwing/rejecting one surfaces as a request error.

> Audit logging is server-side observability — this package depends only on
> `@drakkar.software/starfish-protocol` and registers no cap-cert validator.

See `docs/ts/audit/` for the full guide.
