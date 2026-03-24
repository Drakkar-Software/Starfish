# Changelog

## 1.1.1

### Fixed

- **`SyncManager.push()` signed plaintext instead of encrypted payload** — affects both `starfish-sdk` (Python) and `@starfish/client` (TypeScript). When both encryption and signing were active, the signature was computed over `stableStringify(pendingData)` (plaintext) while the server verified against `stableStringify(payload)` (encrypted wrapper), causing every push to be rejected with `HTTP 400 "Invalid author signature"`. Fixed in `starfish_sdk/sync.py:99` and `src/sync.ts:91`. The server required no changes.

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
