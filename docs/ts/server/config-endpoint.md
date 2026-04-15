# GET /config — Server Config Endpoint

The optional `GET /config` endpoint returns a per-collection client manifest so that clients can discover server capabilities at runtime — without hardcoding collection names, size limits, encryption modes, or public keys.

## Enabling the endpoint

The endpoint is **disabled by default**. Enable it by passing `configEndpoint` to `createSyncRouter` (TypeScript) or `config_endpoint` to `SyncRouterOptions` (Python):

```ts
import { createSyncRouter } from "@drakkar.software/starfish-server"

const sync = createSyncRouter({
  store,
  config,
  roleResolver,
  configEndpoint: { auth: "public" },       // no auth — all collections visible
  // configEndpoint: { auth: "role-filtered" }, // filtered by caller's roles
})
```

```python
from starfish_server import ConfigEndpointOptions
from starfish_server.router import create_sync_router, SyncRouterOptions

sync_router = create_sync_router(SyncRouterOptions(
    store=store,
    config=config,
    role_resolver=role_resolver,
    config_endpoint=ConfigEndpointOptions(auth="public"),
    # config_endpoint=ConfigEndpointOptions(auth="role-filtered"),
))
```

## Auth modes

| Mode | Behaviour |
|---|---|
| `"public"` | No auth check — all collections returned to any caller |
| `"role-filtered"` | `roleResolver` runs; caller sees only collections where their roles intersect `readRoles ∪ writeRoles`. On resolver error, returns empty collections (no 5xx surfaced). |

## Response shape

```ts
import type { ConfigResponse, CollectionClientInfo } from "@drakkar.software/starfish-server"
```

```json
{
  "collections": [
    {
      "name": "posts",
      "maxBodyBytes": 65536,
      "encryption": "none",
      "allowedMimeTypes": ["application/json"],
      "publicKey": "base64encodedkey==",
      "ttlMs": 86400000
    }
  ],
  "namespaces": {
    "tenantA": {
      "collections": [...]
    }
  }
}
```

### CollectionClientInfo fields

| Field | Type | Description |
|---|---|---|
| `name` | `string` | Collection name |
| `maxBodyBytes` | `number` | Maximum push body size in bytes |
| `encryption` | `EncryptionMode` | Encryption mode: `"none"`, `"identity"`, `"server"`, `"delegated"`, or `"group"` |
| `allowedMimeTypes` | `string[]` | MIME types accepted on push |
| `pullOnly` | `boolean?` | Push routes are disabled |
| `pushOnly` | `boolean?` | Pull routes are disabled |
| `queueOnly` | `boolean?` | Nothing is stored — use `push()` directly, never `update()` |
| `clientEncrypted` | `boolean?` | Client-side E2E encryption expected |
| `publicKey` | `string?` | Base64-encoded public key for client-side encryption |
| `ttlMs` | `number?` | Document time-to-live in milliseconds |
| `forceFullFetch` | `boolean?` | Checkpoint-based incremental sync is disabled |

Fields with `?` are omitted when not applicable.

`namespaces` is omitted entirely when no namespaces are configured.

## publicKey — encrypting for a collection

Set `publicKey` on any collection to distribute a public key through the config endpoint:

```ts
// TypeScript config
{
  name: "messages",
  storagePath: "messages/{id}",
  readRoles: ["user"],
  writeRoles: ["user"],
  encryption: "none",
  maxBodyBytes: 65536,
  publicKey: "base64EncodedX25519PublicKey==",
}
```

```python
# Python config
CollectionConfig(
    name="messages",
    storage_path="messages/{id}",
    read_roles=["user"],
    write_roles=["user"],
    encryption="none",
    max_body_bytes=65536,
    public_key="base64EncodedX25519PublicKey==",
)
```

Clients retrieve it via `GET /config` and use it to encrypt data before pushing. The key format and encryption protocol are application-defined — Starfish stores and returns the value verbatim.

## Fetching from the client

### TypeScript client

```ts
import { fetchServerConfig } from "@drakkar.software/starfish-client"

const config = await fetchServerConfig("https://api.example.com/v1")

for (const col of config.collections) {
  console.log(col.name, col.publicKey, col.maxBodyBytes)
}
```

With auth headers:

```ts
const config = await fetchServerConfig("https://api.example.com/v1", {
  headers: { Authorization: `Bearer ${token}` },
})
```

### Python client

```python
from starfish_sdk import fetch_server_config

config = await fetch_server_config("https://api.example.com/v1")

for col in config.collections:
    print(col.name, col.public_key, col.max_body_bytes)
```

With auth headers:

```python
config = await fetch_server_config(
    "https://api.example.com/v1",
    headers={"Authorization": f"Bearer {token}"},
)
```

`fetch_server_config` raises `httpx.HTTPStatusError` on non-2xx responses.

## queueOnly collections

When `queueOnly: true`, the manifest flags this so clients know to call `push()` directly and never `update()`. See [`queue.md`](queue.md#queue-only-collections) for details.
