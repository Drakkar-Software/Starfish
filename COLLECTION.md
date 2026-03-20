# Collection Configuration

Each collection in a Starfish config describes a single synced document (or family of documents). This page covers every available parameter, grouped by concern.

## Minimal example

```json
{
  "version": 1,
  "collections": [
    {
      "name": "settings",
      "storagePath": "users/{identity}/settings",
      "readRoles": ["self"],
      "writeRoles": ["self"],
      "encryption": "none",
      "maxBodyBytes": 65536
    }
  ]
}
```

## Parameter reference

### Core

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | `string` | yes | — | Unique identifier for the collection. |
| `storagePath` | `string` | yes | — | Document key template. May contain `{identity}` or other path parameters (e.g. `users/{identity}/notes`, `posts/{postId}`). Must not start with `/`. |
| `readRoles` | `string[]` | yes | — | Roles allowed to pull. Use `["public"]` for unauthenticated access, `["self"]` for owner-only. |
| `writeRoles` | `string[]` | yes | — | Roles allowed to push. Same role semantics as `readRoles`. |
| `encryption` | `string` | yes | — | Encryption mode: `"none"`, `"identity"`, `"server"`, or `"delegated"`. See [Encryption modes](#encryption-modes). |
| `maxBodyBytes` | `integer` | yes | — | Maximum push payload size in bytes. Requests exceeding this return `413`. |

### Access control modifiers

| Parameter | Type | Default | Description |
|---|---|---|---|
| `pullOnly` | `boolean` | `null` | When `true`, push requests return `405`. Useful for read-only collections. |
| `pushOnly` | `boolean` | `null` | When `true`, pull requests return `405`. Useful for write-only ingest endpoints. |

`pullOnly` and `pushOnly` cannot both be `true` on the same collection.

### Object schema validation

| Parameter | Type | Default | Description |
|---|---|---|---|
| `objectSchema` | `object` (JSON Schema) | `null` | When set, every push validates `body.data` against this [JSON Schema](https://json-schema.org/) before writing. Invalid payloads are rejected with `400`. |

Schema validation applies to **push operations only**. Pull responses are never validated (the data was already validated when it was written).

The `jsonschema` package is included as a default dependency of `starfish-server`.

```jsonc
{
  "name": "profiles",
  "storagePath": "users/{identity}/profiles",
  "readRoles": ["self"],
  "writeRoles": ["self"],
  "encryption": "none",
  "maxBodyBytes": 65536,
  "objectSchema": {
    "type": "object",
    "properties": {
      "name": { "type": "string", "minLength": 1 },
      "age": { "type": "integer", "minimum": 0 },
      "email": { "type": "string", "format": "email" }
    },
    "required": ["name"],
    "additionalProperties": false
  }
}
```

With the schema above, the following push is accepted:
```json
{ "data": { "name": "Alice", "age": 30 }, "baseHash": null }
```

And these are rejected with `400 Schema validation failed`:
```jsonc
{ "data": { "age": 30 }, "baseHash": null }                    // missing required "name"
{ "data": { "name": "Alice", "age": "thirty" }, "baseHash": null } // wrong type
{ "data": { "name": "Alice", "extra": true }, "baseHash": null }   // additional property
```

Any valid JSON Schema draft (Draft 4 through 2020-12) is supported via the `jsonschema` library.

### Allowed MIME types (binary collections)

| Parameter | Type | Default | Description |
|---|---|---|---|
| `allowedMimeTypes` | `string[]` | `["application/json"]` | MIME types this collection accepts on push. Supports wildcard patterns (e.g. `image/*`). |

By default, every collection accepts `application/json` and uses the full JSON sync protocol (conflict detection, timestamps, incremental sync).

Setting `allowedMimeTypes` to non-JSON types (e.g. `["image/png", "image/jpeg"]` or `["image/*"]`) creates a **binary collection** with different semantics:

| Aspect | JSON collection (default) | Binary collection |
|---|---|---|
| Push format | JSON envelope `{ "data": {...}, "baseHash": "..." }` | Raw bytes with `Content-Type` header |
| Pull format | JSON `{ "data": {...}, "hash": "...", "timestamp": ... }` | Raw bytes with original `Content-Type` |
| Conflict detection | Yes (`baseHash` / `409`) | No (last-write-wins overwrite) |
| Timestamps | Yes (per-key) | No |
| Incremental sync | Yes (`?checkpoint=`) | No |
| Empty pull | `200` with `{"data": {}, "hash": ""}` | `404` |

**Examples:**

```jsonc
// Accept only PNG and JPEG images
{ "allowedMimeTypes": ["image/png", "image/jpeg"] }

// Accept any image type (wildcard)
{ "allowedMimeTypes": ["image/*"] }

// Accept PDF only
{ "allowedMimeTypes": ["application/pdf"] }

// Default (JSON sync protocol) — can be omitted
{ "allowedMimeTypes": ["application/json"] }
```

**Push a binary file:**
```bash
curl -X POST /push/users/abc/logo \
  -H "Content-Type: image/png" \
  --data-binary @logo.png
# → {"hash": "sha256hex..."}
```

**Pull a binary file:**
```bash
curl /pull/users/abc/logo
# → raw PNG bytes, Content-Type: image/png, ETag: "sha256hex..."
```

**Constraints:** Binary collections cannot use `identity` or `server` encryption, `objectSchema`, `bundle`, or `remote` replication.

### Rate limiting

Rate limiting applies to **push operations only**. It requires a global `rateLimit` config at the top level of the sync config, which sets the default window and request budget.

#### Global config (top-level)

```json
{
  "version": 1,
  "rateLimit": {
    "windowMs": 60000,
    "maxRequests": 100
  },
  "collections": [...]
}
```

| Parameter | Type | Required | Description |
|---|---|---|---|
| `windowMs` | `integer` | yes | Time window in milliseconds. |
| `maxRequests` | `integer` | yes | Maximum number of push requests per identity per window. |

#### Per-collection config

The `rateLimit` field on a collection controls whether rate limiting is enabled and optionally overrides global defaults.

| Value | Behavior |
|---|---|
| `null` / absent | Rate limiting disabled for this collection. |
| `false` | Rate limiting disabled for this collection. |
| `true` | Rate limiting enabled, using the global `windowMs` and `maxRequests`. |
| `{ "windowMs": …, "maxRequests": … }` | Rate limiting enabled with per-collection overrides. Omitted fields fall back to the global config. |

**Examples:**

```jsonc
// Use global defaults
{ "rateLimit": true }

// Override only maxRequests (windowMs from global)
{ "rateLimit": { "maxRequests": 5 } }

// Override only windowMs (maxRequests from global)
{ "rateLimit": { "windowMs": 1000 } }

// Full override
{ "rateLimit": { "windowMs": 1000, "maxRequests": 10 } }
```

When `rateLimit` is set on a collection but no global `rateLimit` config exists, rate limiting is silently disabled (no error).

Rate limiting is keyed by authenticated identity (the value returned by your `roleResolver`). If no identity is available, it falls back to the client IP via `X-Forwarded-For`, then to a shared `"anonymous"` bucket.

### Cache duration

| Parameter | Type | Default | Description |
|---|---|---|---|
| `cacheDurationMs` | `integer` | `null` | When set, the server adds a `Cache-Control: max-age=<seconds>` header to pull responses. The value is in milliseconds and is converted to whole seconds (truncated). |

This is useful when pull responses can be cached by a CDN, reverse proxy, or HTTP client. It does **not** affect push responses.

```jsonc
// Cache pull responses for 30 seconds
{ "cacheDurationMs": 30000 }

// Cache for 5 minutes
{ "cacheDurationMs": 300000 }
```

### Sync behavior

| Parameter | Type | Default | Description |
|---|---|---|---|
| `forceFullFetch` | `boolean` | `null` | When `true`, the server ignores the `?checkpoint=` query parameter and always returns the full document data. Useful for collections where incremental sync is not meaningful. |
| `clientEncrypted` | `boolean` | `null` | Marks the collection as client-side encrypted. Implies `forceFullFetch` behavior (the server cannot inspect encrypted data to compute deltas). |

### Bundles

Collections with the same `bundle` value share a `storagePath` and are served together in a single pull response.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `bundle` | `string` | `null` | Bundle group name. All collections in the same bundle must have the same `storagePath` and use `"identity"` encryption. |

```json
[
  { "name": "settings", "storagePath": "users/{identity}", "bundle": "user-data", "encryption": "identity", ... },
  { "name": "favorites", "storagePath": "users/{identity}", "bundle": "user-data", "encryption": "identity", ... }
]
```

`GET /pull/users/:identity` returns all bundled collections in one response. Push remains per-collection: `POST /push/users/:identity/settings`.

### Replication (remote)

Adding a `remote` block makes the collection a replica that syncs from a primary Starfish server.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `remote` | `object` | `null` | When set, this collection is replicated from a remote primary. See below. |

#### Remote config

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `url` | `string` | yes | — | Base URL of the primary server (e.g. `https://primary.example.com/v1`). |
| `pullPath` | `string` | yes | — | Pull endpoint path on the primary (e.g. `/pull/posts/featured`). Must be static (no template variables). |
| `pushPath` | `string` | no | `null` | Push endpoint path on the primary. Required for `push_through` and `bidirectional` write modes. |
| `intervalMs` | `integer` | no | `60000` | Sync interval in ms for the `scheduled` trigger. |
| `headers` | `object` | no | `{}` | Static HTTP headers sent to the primary (e.g. `{"Authorization": "Bearer token"}`). |
| `writeMode` | `string` | no | `"pull_only"` | How client writes are handled. See [Write modes](#write-modes). |
| `syncTriggers` | `string[]` | no | `["scheduled"]` | Events that trigger a sync. See [Sync triggers](#sync-triggers). |
| `webhookSecret` | `string` | no | `null` | HMAC-SHA256 secret for verifying webhook notifications. Required when `"webhook"` is in `syncTriggers`. |
| `onPullMinIntervalMs` | `integer` | no | `null` | Minimum cooldown in ms between `on_pull` syncs. When set and the cooldown hasn't elapsed, the replica serves cached data without hitting the primary. |

#### Write modes

| Mode | Client reads | Client writes | Sync behavior |
|---|---|---|---|
| `pull_only` | Allowed | Rejected (405) | Replaces local data with primary's |
| `push_through` | Allowed | Forwarded to primary | Replaces local data after forward |
| `bidirectional` | Allowed | Stored locally | Remote-wins deep merge on sync |
| `push_only` | Rejected (405) | Stored locally | No sync from primary |

#### Sync triggers

| Trigger | When it fires |
|---|---|
| `scheduled` | Every `intervalMs` in a background task. |
| `webhook` | When the primary sends a `POST /replica/notify` notification. |
| `on_pull` | Before each client `GET /pull/…` request (respects `onPullMinIntervalMs` cooldown). |

#### Remote collection constraints

- `storagePath` must be static (no `{identity}` or other template variables).
- Cannot be `pushOnly`.
- Cannot be part of a `bundle`.
- Cannot use `"delegated"` encryption.

## Encryption modes

| Mode | Key derivation | Who can read | Use case |
|---|---|---|---|
| `none` | — | Anyone with access | Public or non-sensitive data |
| `identity` | `HKDF(secret, identity)` | Only the owning user | Per-user private data |
| `server` | `HKDF(secret, serverIdentity)` | All server code | Server-wide secrets |
| `delegated` | Client-managed | Only the client | End-to-end encrypted vaults |

`delegated` implies `clientEncrypted` behavior (full-fetch only, no incremental sync).

## Full example

```json
{
  "version": 1,
  "rateLimit": {
    "windowMs": 60000,
    "maxRequests": 100
  },
  "collections": [
    {
      "name": "settings",
      "storagePath": "users/{identity}/settings",
      "readRoles": ["self"],
      "writeRoles": ["self"],
      "encryption": "identity",
      "maxBodyBytes": 65536,
      "rateLimit": true,
      "cacheDurationMs": 10000
    },
    {
      "name": "posts",
      "storagePath": "posts/{postId}",
      "readRoles": ["public"],
      "writeRoles": ["admin", "owner"],
      "encryption": "none",
      "maxBodyBytes": 131072,
      "rateLimit": { "maxRequests": 10 },
      "cacheDurationMs": 60000,
      "objectSchema": {
        "type": "object",
        "properties": {
          "title": { "type": "string", "minLength": 1 },
          "body": { "type": "string" },
          "tags": { "type": "array", "items": { "type": "string" } }
        },
        "required": ["title", "body"]
      }
    },
    {
      "name": "audit-log",
      "storagePath": "audit/{identity}",
      "readRoles": ["admin"],
      "writeRoles": ["self"],
      "encryption": "server",
      "maxBodyBytes": 262144,
      "pullOnly": true
    },
    {
      "name": "ingest",
      "storagePath": "events/{identity}",
      "readRoles": [],
      "writeRoles": ["self"],
      "encryption": "none",
      "maxBodyBytes": 32768,
      "pushOnly": true,
      "rateLimit": { "windowMs": 1000, "maxRequests": 5 }
    },
    {
      "name": "vault",
      "storagePath": "users/{identity}/vault",
      "readRoles": ["self"],
      "writeRoles": ["self"],
      "encryption": "delegated",
      "maxBodyBytes": 65536
    }
  ]
}
```
