# Changelog

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
