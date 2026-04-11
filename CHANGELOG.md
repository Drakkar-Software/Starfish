# Changelog

## 1.9.0

### Added

#### Server (TypeScript)

- **Version bump to 1.6.0** — reflects the namespace feature added in 1.8.0 (package version was not bumped at that time).

#### Server (Python)

- **Version bump to 1.4.0** — brings the Python server to feature parity with TypeScript 1.6.0.
- **Collection namespaces** — Optional `namespaces` field on `SyncConfig` mirrors the TypeScript feature: collections grouped under `/{namespace}/pull/...` and `/{namespace}/push/...`, each with its own `/{namespace}/batch/pull` endpoint. `NamespaceConfig` type exported from the package. Namespace names must match `[a-zA-Z0-9_-]+` and cannot use reserved names (`pull`, `push`, `health`, `batch`).
- **TTL enforcement in router** — `ttlMs` field added to `CollectionConfig` (Python snake_case alias: `ttl_ms`). Expired documents return empty data on pull. The utility `is_expired()` was already exported; it is now wired into the pull and batch-pull handlers.
- **Field-level permissions** — `fieldPermissions` field added to `CollectionConfig` (alias: `field_permissions`). New `FieldPermission` model with `readRoles`/`writeRoles`. Restricted fields are stripped from pull responses and rejected on push. `FieldPermission` exported from the package.
- **Batch pull endpoint** — `GET /batch/pull?collections=col1,col2` endpoint added at root and per-namespace, matching the TypeScript API.

## 1.8.0

### Added

#### Server (TypeScript)

- **Queue documentation** — Added `docs/ts/server/queue.md` covering `QueueConfig` fields (`topic`, `includeParams`), the `Queue` interface, `MemoryQueue` / `CustomQueue` built-in implementations, server wiring, custom backend guide, and Python equivalents. Updated README queue section with TypeScript examples alongside the existing Python ones.

#### Server (TypeScript)

- **Collection namespaces** — Optional `namespaces` field on `SyncConfig` groups collections under a URL prefix: `/{namespace}/pull/...` and `/{namespace}/push/...`. Each namespace has its own `/{namespace}/batch/pull` endpoint that only searches within that namespace. Root-level collections (under `collections`) are unaffected and continue to work at `/pull/...` and `/push/...`. Collection names must be unique within each scope (root or a given namespace), but the same name may appear in different namespaces — enabling multi-tenant configs where every tenant has a `"settings"` collection. Namespace names must match `[a-zA-Z0-9_-]+` and cannot use reserved names (`pull`, `push`, `health`, `batch`). New `NamespaceConfig` type exported from the package. See `docs/ts/client/20-namespaces.md` for the full guide.

## 1.7.0

### Added

#### Client (TypeScript)

- **`createDebouncedPush(syncManager, options)`** — Store-less debounced push for one-way publishing workflows (public pages, derived snapshots). Calls `syncManager.push(doc)` directly without requiring a Zustand store. Options: `serialize` (required), `delayMs`, `warnBytes`, `maxBytes`, `onSizeWarning`, `onSizeExceeded`, `onError`. Includes the same encrypted payload size guard as `createDebouncedSync`. `onError` defaults to `console.warn` on push failure.
- **`createMobileLifecycle(store, deps, options?)`** — Wires React Native `AppState` and `NetInfo` events to a Starfish store. Uses dependency injection (pass `AppState` from `react-native` and optionally `NetInfo` from `@react-native-community/netinfo`) so no React Native imports are needed in this package. Background → flush dirty data; foreground → pull remote changes (only if online + not syncing); NetInfo → `setOnline()`. Returns a cleanup function. Options: `pullOnForeground` (default `true`), `flushOnBackground` (default `true`).

## 1.6.0

### Added

#### Client (TypeScript)

- **Passphrase identity kit** (`./identity` subpath) — Serverless/passwordless auth from a single secret. `generatePassphrase(wordCount?, wordlist?)` produces a crypto-secure BIP-39-style passphrase (default 12 words, 96 bits of entropy). `deriveCredentials(passphrase)` deterministically derives `{ authToken, userId, encryptionSecret, encryptionSalt }` — plug directly into `StarfishClient` auth header and `SyncManager` encryption options. `buildInviteUrl(baseUrl, payload)` / `parseInviteUrl(url)` encode/decode arbitrary invite payloads as URL-safe base64 tokens.
- **`onRemoteUpdate` callback on `createStarfishStore`** — Fires only when remote data arrives via `pull()`, never on local `set()`. Eliminates the manual `isRestoring` guard pattern that prevented subscribe-triggered re-push loops. Pass `onRemoteUpdate: (data) => restore(data)` instead of wiring a store subscription that checks `!state.dirty`.
- **`subscribeSyncStatus(store, callback)`** — Framework-agnostic (non-React) subscription to derived sync status changes. Fires immediately with current status, then on every transition. Deduplicates consecutive equal values. Returns an unsubscribe function. Complements the existing `useSyncStatus` React hook for non-React environments.
- **`createDebouncedSync(store, options?)`** — Debounces push calls triggered by rapid user edits. Returns `{ notify, cancel }`. Default 2000ms delay; resets on each `notify()`. Pre-push size guard: estimates encrypted payload size (JSON byte count × 1.34 for base64 overhead), calls `onSizeWarning(bytes)` above `warnBytes` (default 900KB) and blocks the push with `onSizeExceeded(bytes)` above `maxBytes` (default 1MB). Falls back to `console.warn`/`console.error` when no callback is provided.
- **`createMultiStoreSync(options)`** — Serializes multiple domain Zustand stores into a single versioned Starfish document and restores them back. Options: `slices` (map of store slice keys to `{ getState, restore }` helpers), `version` (current schema version), `migrations` (map of `fromVersion` → migration function). Migrations run sequentially on restore when the document version is behind. Useful for apps that sync more than one logical domain (guests, vendors, planning…) in one Starfish collection.
- **Collection pattern guide** (`docs/ts/client/19-collection-patterns.md`) — Five ready-to-use server + client configuration recipes: Private Vault (self r/w + E2E encryption), Public Page (public r, owner w), Public Roster (per-record tokens), Submission Inbox (owner r, public w, TTL), and Claim Tracker. Includes a section on combining patterns, idempotent anonymous submissions with `update()`, conflict retry, and error handling.

## 1.5.0

### Added

#### Server (TypeScript + Python)

- **CORS middleware** — Configurable CORS with origin whitelist, credentials, methods, headers, and max-age. Pass `cors: true` (permissive) or `cors: { origin: "https://app.example.com", credentials: true }` to `SyncRouterOptions`. Rejects `credentials: true` with wildcard origin at startup (CORS spec violation). Python: `configure_middleware(app, cors=CorsConfig(...))`.
- **Security headers** — Adds `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`, `X-XSS-Protection`, and `Referrer-Policy` to all responses. Pass `securityHeaders: true` or customize per-header. Python: `SecurityHeadersMiddleware`.
- **Response compression** — GZip middleware for Python via `configure_middleware(app, compression=True)`.
- **ETag / conditional requests** — Pull responses include an `ETag` header with the document hash. Clients sending `If-None-Match` receive `304 Not Modified` when the hash matches, avoiding redundant data transfer. Works for both JSON and binary collections.
- **Request timeout** — Per-request timeout middleware (returns `408` on expiry). Pass `requestTimeoutMs` to `SyncRouterOptions`. Python: `RequestTimeoutMiddleware`.
- **Graceful shutdown** — `createGracefulShutdown({ replicaManager, queue, onShutdown })` registers SIGTERM/SIGINT handlers and cleanly stops replicas, queues, and custom resources. Python: `GracefulShutdown` class with `register()`/`unregister()`.
- **Structured server logging** — `ServerLogger` interface with `createConsoleLogger()`, `createJsonLogger()`, and `createNoopLogger()`. Pass `logger` to `SyncRouterOptions`. Python: `ConsoleLogger`, `JsonLogger`, `NoopLogger`.
- **Audit logging** — `AuditLogger` interface records who pulled/pushed which collection, when, and whether it succeeded. Pass `auditLogger` to `SyncRouterOptions`. Built-in: `createConsoleAuditLogger()`, `createCallbackAuditLogger(cb)`. Python: async-compatible `ConsoleAuditLogger`, `CallbackAuditLogger` (accepts sync or async callbacks).
- **Field-level permissions** — Optional `fieldPermissions` on collections: per-field `readRoles` (strip fields on pull) and `writeRoles` (reject push if user modifies restricted fields). Example: `fieldPermissions: { email: { readRoles: ["admin"], writeRoles: ["admin"] } }`.
- **Batch pull endpoint** — `GET /batch/pull?collections=col1,col2` pulls multiple collections in one request. Enforces per-collection auth; unauthorized collections return `{ error: "Forbidden" }`.
- **TTL / document expiration** — Optional `ttlMs` on collections. Expired documents return empty data on pull. TTL is check-on-read only (no background cleanup). `isExpired(timestamp, ttlMs)` utility exported.
- **OpenAPI spec generation** — `generateOpenApiSpec(config, { title, version, serverUrl })` produces an OpenAPI 3.0.3 spec from `SyncConfig`. Python: `generate_openapi_spec()`.
- **Docker support** — Dockerfiles for both TS and Python servers, `docker-compose.yml` for local development, and `.dockerignore`.

#### Client (TypeScript)

- **Request deduplication** — `createDedupFetch(baseFetch?)` wraps fetch to deduplicate concurrent identical GET requests. Multiple callers awaiting the same URL share one network request.
- **IndexedDB storage adapter** — `createIndexedDBStorage({ dbName, storeName })` implements Zustand's `StateStorage` interface backed by IndexedDB for data larger than localStorage's 5-10MB limit. Retries on DB open failure.
- **Extended performance metrics** — `SyncMetrics` interface adds `bytesTransferred`, `compressedSize`, `conflictCount`, `retryCount`, `cacheHit` to `pullSuccess`/`pushSuccess` logger calls (backward compatible). `createMetricsCollector()` accumulates per-store totals/averages with `getSummary()` and `reset()`.
- **Conflict field indicators** — `withConflictMeta(resolver)` wraps any `ConflictResolver` to return `ConflictMeta` alongside merged data: `{ conflictedFields: string[], resolvedBy: "local" | "remote" | "merged", timestamp }`. Uses structural comparison (not JSON.stringify).
- **Background Sync API** — `registerBackgroundSync({ tag })` registers a sync tag with the service worker. `isBackgroundSyncSupported()` checks browser support. Note: actual sync event handling must be implemented in your service worker.
- **React Suspense integration** — `createSuspenseResource(fetcher)` creates a resource that throws a Promise while loading (Suspense protocol). After resolution, `read()` returns data synchronously.
- **Data export/import** — `exportData(data, { format, pretty })` and `importData(raw, format)` for JSON and CSV. `exportToBlob(data, opts)` creates a downloadable Blob.
- **Service Worker utilities** — `registerServiceWorker(scriptUrl, { scope, onUpdate })`, `unregisterServiceWorkers()`, and `isServiceWorkerSupported()`.

### Fixed

- **Rate limiter unbounded memory** — `RateLimiter` now caps bucket count at `maxBuckets` (default 10,000), evicting oldest entries when full. Prevents memory exhaustion via `X-Forwarded-For` header spoofing.

## 1.4.1

### Added

- **Snapshot history** — `SnapshotHistory` class for maintaining labeled snapshots of document state with optional `localStorage` persistence. Methods: `take(label, data)`, `restore(index)`, `list()`, `clear()`. Configurable `maxSnapshots` (default 20).
- **Polling utilities** — `startPolling(pullFn, getState, intervalMs?)` for periodic sync with cleanup. `startAdaptivePolling(pullFn, getState, options?)` adapts interval to `navigator.connection.effectiveType` with `pause`/`resume`/`stop` controls. Framework-agnostic via `PollableState` interface.
- **React hooks** (in `./zustand` subpath) — `useCrossTabSync(store, name)` wraps `setupCrossTabSync` with React lifecycle. `useConnectivity(store)` binds browser online/offline events to `setOnline`. `useLastSynced(store)` returns a human-readable label ("Just now", "15s ago", "2m ago") that auto-updates.
- **`aggregateSyncStatus(statuses)`** — Pure function to combine multiple `SyncStatus` values into a worst-case aggregate (error > syncing > pending > offline > synced).

### Fixed

- **`pruneTombstones` silently dropped string timestamps** — Now handles both numeric epoch and ISO-8601 string `_deletedAt` values, consistent with the rest of the resolvers module.
- **`createSoftDeleteResolver` rejected string `_deletedAt`** — Now accepts both numeric and string timestamps for tombstone detection.
- **`SyncManager.pull()` returned delta on incremental pulls** — Now returns the full merged document in `result.data`, not just the server's delta.
- **Conflict resolution state corruption** — `lastHash`/`lastCheckpoint` are now updated after successful decryption, preventing inconsistent state if decryption fails during conflict retry.
- **`classifyError` did not handle `status: 0`** — Now classifies as `"network"`. Also validates that `status` is a number before comparing.
- **`BlobPullResult.hash` was empty string for missing ETag** — Now `string | null` to make the absence explicit.
- **Empty `Retry-After` header caused tight retry loop** — `Retry-After: ""` now falls back to exponential backoff instead of 0ms delay.
- **Circuit breaker stuck in half-open on 4xx** — Non-5xx responses now record success (server is reachable), preventing the breaker from staying in half-open permanently.
- **Compression fallback on stream errors** — `createCompressedFetch` now catches compression errors and falls back to uncompressed request.
- **Unhandled promise rejections** — Fire-and-forget `flush()` calls in Zustand and Legend `set()`/`setOnline()` actions, and `pullFn()` in polling utilities, now have `.catch()` handlers.
- **Unsafe error casts** — All `(err as Error).message` patterns replaced with `err instanceof Error ? err.message : String(err)` across Zustand, Legend, and SyncManager.
- **Migration errors lacked context** — Migration function failures now include the version step that failed (e.g., "Migration from version 2 to 3 failed: ...").
- **`SnapshotHistory` corrupted data handling** — Constructor validates parsed localStorage is an array. `restore()` catches JSON parse errors and returns `undefined`.
- **Broadcast storage fallback payload validation** — `setupStorageFallback` now validates the shape of parsed JSON before applying it to the store.

## 1.4.0

### Added

- **Structured logging** — `SyncLogger` interface with `consoleSyncLogger` and `noopSyncLogger` implementations. Integrated into `SyncManager` via optional `logger` and `loggerName` options. Emits `pullStart`, `pullSuccess`, `pullError`, `pushStart`, `pushSuccess`, `pushError`, and `conflict` events with timing data.
- **Retry / Circuit Breaker** (`./fetch` subpath) — `createRetryFetch` with exponential backoff and `Retry-After` header support (both seconds and HTTP-date formats). `CircuitBreaker` class with CLOSED/OPEN/HALF-OPEN state machine (failure during half-open immediately re-opens). `createResilientFetch` combines both. `createCompressedFetch` for gzip request body compression via `CompressionStream`.
- **Error classification** — `classifyError(err)` categorizes errors into `network`, `auth`, `conflict`, `rate-limited`, `server`, `client`, or `unknown`. Exported from main entrypoint.
- **Schema migration** — `createMigrator(config)` applies versioned migration chains with eager validation at construction and forward-compatibility guard. Uses `_schemaVersion` field convention.
- **Pre-push validation** — `validate` option on `SyncManagerOptions` accepts a `Validator` function. Throws `ValidationError` before any network call. `createSchemaValidator(ajv, schema)` factory for Ajv integration.
- **Binary blob sync** — `StarfishClient.pullBlob(path)` and `pushBlob(path, data, contentType)` for binary collections. Returns `BlobPullResult` (ArrayBuffer + hash from ETag + contentType) and `BlobPushResult` (hash). Last-write-wins (no conflict detection).
- **Conflict resolvers** — `createUnionMerge()` for ID-based array union with per-item `updatedAt` comparison (handles both numeric and ISO-8601 timestamps). `createSoftDeleteResolver()` extends union merge with tombstone awareness. `timestampWinner()` for document-level winner-take-all. `pruneTombstones()` utility removes expired soft-deleted items with configurable TTL.
- **Cross-tab sync** (`./broadcast` subpath) — Framework-agnostic `BroadcastableStore` interface. `setupBroadcastSync` (BroadcastChannel), `setupStorageFallback` (localStorage events), and `setupCrossTabSync` (auto-detect). Works with both Zustand and Legend State stores.
- **React hooks** (in `./zustand` subpath) — `useStarfish(store)`, `useStarfishData(store, selector?)`, `useSyncStatus(store)`, and `deriveSyncStatus(state)`. `useSyncInit(config | null)` manages the full sync lifecycle (create client/manager/store, pull on mount, `onData` callback for domain restoration, teardown on unmount/config change).
- **`restore()` method** on `StarfishStore` — Updates store data without marking dirty or triggering flush. Prevents pull-to-push feedback loops.
- **Testing utilities** (`./testing` subpath) — `createMockClient(overrides?)` with call tracking (`pullCalls`, `pushCalls`). `createMockFetch(pullResponse?, pushResponse?)` and `createConflictFetch(conflictPullResponse, successPushResponse?)` for integration tests.
- **Snapshot history** — `SnapshotHistory` class for maintaining labeled snapshots of document state with optional `localStorage` persistence. Methods: `take(label, data)`, `restore(index)`, `list()`, `clear()`. Configurable `maxSnapshots` (default 20).
- **Polling utilities** — `startPolling(pullFn, getState, intervalMs?)` for periodic sync with cleanup. `startAdaptivePolling(pullFn, getState, options?)` adapts interval to `navigator.connection.effectiveType` with `pause`/`resume`/`stop` controls. Framework-agnostic via `PollableState` interface.
- **React hooks** (in `./zustand` subpath) — `useCrossTabSync(store, name)` wraps `setupCrossTabSync` with React lifecycle. `useConnectivity(store)` binds browser online/offline events to `setOnline`. `useLastSynced(store)` returns a human-readable label ("Just now", "15s ago", "2m ago") that auto-updates.
- **`aggregateSyncStatus(statuses)`** — Pure function to combine multiple `SyncStatus` values into a worst-case aggregate (error > syncing > pending > offline > synced).

### Changed

- **`SyncManagerOptions.name` renamed to `loggerName`** — Avoids ambiguity with the store `name` field.
- **`./react` subpath removed** — React hooks moved into `./zustand` subpath (they are zustand-specific).
- **Version bump** — `@drakkar.software/starfish-client` 1.3.2 → 1.4.0.

### New subpath exports

| Subpath | Contents |
|---------|----------|
| `./fetch` | `createRetryFetch`, `CircuitBreaker`, `createResilientFetch`, `createCompressedFetch` |
| `./broadcast` | `setupBroadcastSync`, `setupStorageFallback`, `setupCrossTabSync`, `BroadcastableStore` |
| `./testing` | `createMockClient`, `createMockFetch`, `createConflictFetch` |

## 1.3.2

Re-release of 1.3.1 (CI publishing fix — no code changes).

## 1.3.1

### Changed

- **TS packages published under `@drakkar.software` scope** — Packages renamed to `@drakkar.software/starfish-protocol`, `@drakkar.software/starfish-client`, `@drakkar.software/starfish-server`.

## 1.3.0

### Added

- **TypeScript server** (`@drakkar.software/starfish-server`) — Full TypeScript port of the Python server, built with [Hono](https://hono.dev/) for Cloudflare Workers / edge runtime compatibility. Replicates all Python server features: config system, pull/push protocol, timestamps, encryption (AES-256-GCM via Web Crypto API), role-based auth, rate limiting, binary collections, bundled collections, queue events, and replica management.
- **Cross-language protocol test vectors** — New shared test vector files (`tests/test-vectors/protocol-push.json`, `protocol-timestamps.json`, `http-errors.json`) consumed by both Python (pytest) and TypeScript (vitest) to guarantee identical protocol behavior across implementations.
- **`setAjv()` for serverless JSON Schema validation** — In environments without `require()` (e.g. Cloudflare Workers), call `setAjv(ajvInstance)` to provide an Ajv instance for `objectSchema` validation.
- **`FilesystemObjectStore` (Node.js)** — Available via `@drakkar.software/starfish-server/node` subpath export. Atomic writes, sidecar metadata for binary content types, recursive directory listing.

### Fixed

- **`workspace:*` not resolved on npm publish** — The CI publish workflow now explicitly sets the `@drakkar.software/starfish-protocol` dependency version from the git tag before publishing client and server packages.

## 1.2.0

### Added

- **Generic queue abstraction** — New `AbstractQueue` interface (ABC) for publishing data-change events after successful pushes, following the same pattern as `AbstractObjectStore`. Built-in implementations: `MemoryQueue` (testing), `CustomQueue` (callback-based), `NatsQueue` (NATS).
- **Per-collection queue config** (`queue`) — Collections can opt in to change events with `"queue": true` (topic defaults to collection name) or `"queue": { "topic": "…", "includeParams": true }` for custom topic and path parameter inclusion.
- **NATS support** — `NatsQueue` with `NatsQueueOptions` for publishing to a NATS server. Install with `pip install starfish-server[nats]`.
- **Binary and bundled push events** — Queue events now fire for binary collection pushes and bundled collection pushes (previously, only JSON pushes triggered notifications).

### Removed

- **Webhook/notify system** — Removed `NotificationPublisher`, `SubscriptionStore`, `Subscription`, `create_replica_router`, and the `POST /replica/subscribe` and `POST /replica/notify` HTTP endpoints. Replaced by the queue abstraction above.
- **`SyncTrigger.WEBHOOK`** — The `"webhook"` sync trigger is removed. Replicas can use `"scheduled"` or `"on_pull"` triggers; for push-triggered replication, subscribe to the queue directly.
- **`RemoteConfig.webhookSecret`** — No longer needed without webhook endpoints.
- **`ReplicaManager.on_notification()`** and **`ReplicaManager._subscribe()`** — Removed along with the `self_base_url` constructor parameter.

### Changed

- **`SyncRouterOptions.notification_publisher`** replaced by **`SyncRouterOptions.queue`** — Pass an `AbstractQueue` instance to enable change-event publishing.
- **TS packages now publish to npm** instead of GitHub Packages. Renamed from `@starfish/protocol` / `@starfish/client` to `@drakkar.software/starfish-protocol` / `@drakkar.software/starfish-client`.

## 1.1.1

### Fixed

- **`SyncManager.push()` signed plaintext instead of encrypted payload** — affects both `starfish-sdk` (Python) and `starfish-client` (TypeScript). When both encryption and signing were active, the signature was computed over `stableStringify(pendingData)` (plaintext) while the server verified against `stableStringify(payload)` (encrypted wrapper), causing every push to be rejected with `HTTP 400 "Invalid author signature"`. Fixed in `starfish_sdk/sync.py:99` and `src/sync.ts:91`. The server required no changes.

## 1.1.0

### Added

- **Per-collection rate limit overrides** — The `rateLimit` field on a collection now accepts an object `{ "windowMs": …, "maxRequests": … }` to override the global defaults. `true` still works for global defaults, `false`/`null` disables.
- **Cache duration** (`cacheDurationMs`) — Optional `Cache-Control: max-age` header on pull responses. Non-public collections use the `private` directive.
- **Object schema validation** (`objectSchema`) — Optional JSON Schema on a collection. When set, push payloads are validated against it before writing; invalid data returns `400`. The `jsonschema` package is now a default dependency of `starfish-server`.
- **Binary collections** (`allowedMimeTypes`) — Collections can declare accepted MIME types with wildcard patterns (e.g. `["image/*"]`). Binary collections accept raw file uploads on push and return raw bytes on pull, with simple overwrite semantics (no conflict detection). Defaults to `["application/json"]` (existing JSON sync protocol).
- **COLLECTION.md** — Full parameter reference for all collection config fields.

### Changed

- **Health endpoint** — `GET /health` now returns `{ "ok": true, "ts": <epoch_ms> }` instead of `{ "status": "ok" }`.

### Fixed

- **Rate limiter not persisting state across requests** — FastAPI's dependency injection was re-creating `RateLimiter` instances on every request instead of reusing the one created at startup. Push handlers now use a factory function to capture the rate limiter in a proper closure.
