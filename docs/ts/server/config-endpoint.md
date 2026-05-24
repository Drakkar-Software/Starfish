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
| `encryption` | `EncryptionMode` | Encryption mode: `"none"` or `"delegated"` |
| `allowedMimeTypes` | `string[]` | MIME types accepted on push |
| `pullOnly` | `boolean?` | Push routes are disabled |
| `pushOnly` | `boolean?` | Pull routes are disabled |
| `appendOnly` | `{ type: "by_timestamp", field?, persist? }?` | Append-only mode config — see [Append-Only Collections](append-only-collections.md) |
| `ttlMs` | `number?` | Document time-to-live in milliseconds |
| `forceFullFetch` | `boolean?` | Checkpoint-based incremental sync is disabled |

Fields with `?` are omitted when not applicable.

`namespaces` is omitted entirely when no namespaces are configured.

### Encryption modes

Starfish 3.0 advertises exactly two modes through the manifest:

| Mode | Server stores | Decryption |
|------|---------------|-----------|
| `"none"` | Plaintext JSON | n/a |
| `"delegated"` | AES-256-GCM ciphertext + plaintext `_keyring` document | Per-recipient X25519 wraps inside the keyring document |

The keyring is a regular document at `<storagePath>/_keyring` by default. See [Multi-Recipient Delegated Encryption](../client/23-multi-recipient-delegated.md) for the schema and the client-side wiring.

### Access modes (composing `requireAuth` + roles)

Starfish has **no `mode` field** — public / invite-only / owner-only-private are all expressed by composing the existing `requireAuth` and `readRoles`/`writeRoles` knobs. Three common patterns:

| Pattern | `requireAuth` | `readRoles` | `writeRoles` | Notes |
|---|---|---|---|---|
| **Public** | `false` | `["public"]` | `["public"]` | Anonymous requests accepted. Most permissive — use for guestbook-style collections only. |
| **Invite-only (default)** | `true` (default) | `["cap:read:<col>"]` | `["cap:write:<col>"]` | Cap-cert with matching scope required. Standard pattern for delegated collections. |
| **Owner-only-private** | `true` | `["admin:<ownerUserId>"]` | `["admin:<ownerUserId>"]` | Only caps bearing the owner role (typically synthesized for `kind: "device"` caps issued by the owner's root). Members minted via `mintMemberCap` for other users will **not** match these roles and will 403. |

The `cap:read:<col>` / `cap:write:<col>` / `cap:list:<col>` roles are synthesized automatically by `createCapCertRoleResolver` from each cap's `scope.ops` × `scope.collections`. Custom enrichers may layer on top (e.g. `delegated:<ownerId>:<col>` for member caps). See [Capability Certificates](../client/25-capability-certs.md#two-kinds) for the full role-synthesis rules.

## `keyringPath` — overriding the keyring location (server-side)

For `encryption: "delegated"` collections, the server defaults to storing the recipient keyring at `<storagePath>/_keyring`. To override, set `keyringPath` on the `CollectionConfig`:

```ts
// TypeScript config (server-side SyncConfig)
{
  name: "messages",
  storagePath: "messages/{id}",
  readRoles: ["cap:read:messages"],
  writeRoles: ["cap:write:messages"],
  encryption: "delegated",
  maxBodyBytes: 65536,
  allowedMimeTypes: ["application/json"],
  keyringPath: "messages/_keyring",   // optional override; defaults to "messages/_keyring"
}
```

```python
# Python config (server-side SyncConfig)
CollectionConfig(
    name="messages",
    storage_path="messages/{id}",
    read_roles=["cap:read:messages"],
    write_roles=["cap:write:messages"],
    encryption="delegated",
    max_body_bytes=65536,
    keyring_path="messages/_keyring",  # optional override
)
```

`keyringPath` is a server-side configuration knob only — it is **not** echoed back through `GET /config`. Clients learn the keyring location implicitly (`<storagePath>/_keyring` unless your application tells them otherwise).

## Fetching from the client

### TypeScript client

```ts
import { fetchServerConfig } from "@drakkar.software/starfish-client"

const config = await fetchServerConfig("https://api.example.com/v1")

for (const col of config.collections) {
  console.log(col.name, col.encryption, col.maxBodyBytes)
}
```

With auth headers (role-filtered mode — pass the same `Authorization: Cap <base64-cap-cert>` header your `StarfishClient` would normally send):

```ts
const config = await fetchServerConfig("https://api.example.com/v1", {
  headers: {
    Authorization: `Cap ${capCertBase64}`,
    // The /config endpoint does not require the request-signature triplet,
    // but most resolvers will still accept (and ignore) it.
  },
})
```

### Python client

```python
from starfish_sdk import fetch_server_config

config = await fetch_server_config("https://api.example.com/v1")

for col in config.collections:
    print(col.name, col.encryption, col.max_body_bytes)
```

With auth headers:

```python
config = await fetch_server_config(
    "https://api.example.com/v1",
    headers={"Authorization": f"Cap {cap_cert_base64}"},
)
```

`fetch_server_config` raises `httpx.HTTPStatusError` on non-2xx responses.

## Append-only collections

When `appendOnly` is set, the manifest exposes its configuration so clients can discover the collection's behavior at runtime. See [Append-Only Collections](append-only-collections.md) for details.
