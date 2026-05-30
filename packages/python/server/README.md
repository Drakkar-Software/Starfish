# starfish-server

Python server for [Starfish](../../../README.md). FastAPI-based, with pluggable storage backends (memory, filesystem, S3-compatible).

## Install

```bash
pip install starfish-server
# Optional extras:
pip install "starfish-server[s3]"     # S3-compatible storage
pip install "starfish-server[nats]"   # NATS queue backend
```

## What's in v3.0

Starfish 3.0 removes server-held encryption entirely. The two encryption modes are:

```python
EncryptionMode = Literal["none", "delegated"]
```

- `"none"` — server stores plaintext.
- `"delegated"` — server stores opaque `{"_encrypted": ..., "_epoch": N}` ciphertext and a plaintext keyring document at `<storage_path>/_keyring` (or the explicit `keyring_path`). The server never sees a CEK.

The v2 `"identity"`, `"server"`, and `"group"` modes are gone. So are the `encryption_secret`, `server_encryption_secret`, `server_identity`, `identity_encryption_info`, `server_encryption_info`, `signature_verifier`, `EncryptedObjectStore`, `client_encrypted`, and `public_key` symbols. See [docs/migration/v2-to-v3.md](../../../docs/migration/v2-to-v3.md).

## Quickstart (v3)

```python
from fastapi import FastAPI
from starfish_server import (
    MemoryObjectStore,
    parse_config_json,
    create_cap_cert_role_resolver,
    create_in_memory_nonce_cache,
    create_in_memory_revocation_store,
)
from starfish_server.router import create_sync_router, SyncRouterOptions

store = MemoryObjectStore()

config = parse_config_json("""{
  "version": 1,
  "collections": [
    {
      "name": "notes",
      "storagePath": "notes/{identity}",
      "readRoles":  ["cap:read:notes", "self"],
      "writeRoles": ["cap:write:notes", "self"],
      "encryption": "delegated",
      "maxBodyBytes": 65536
    }
  ]
}""")

router = create_sync_router(SyncRouterOptions(
    store=store,
    config=config,
    role_resolver=create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        allow_anonymous=True,
    ),
))

app = FastAPI()
app.include_router(router, prefix="/v1")
```

## Cap-cert auth

`create_cap_cert_role_resolver` is the v3 default role resolver. For every authenticated request it:

1. Parses `Authorization: Cap <base64(stable_stringify(cap))>`.
2. Verifies the cap-cert (signature, `nbf`/`exp` ± skew, `user_id` derivation, kind-specific well-formedness).
3. Verifies the per-request signature using `X-Starfish-Sig` / `X-Starfish-Ts` / `X-Starfish-Nonce`.
4. Checks the nonce against an LRU cache (replay protection) and the timestamp against a ±5 min clock skew.
5. Consults the `RevocationStore` for the cap's `nonce` and (for member caps) the subject.
6. Binds `auth.identity` per `kind`: `device` → `iss_user_id`, `member` → `sub_user_id`.
7. Synthesizes roles: `cap:<op>:<collection>` for each (op, collection) pair; `delegated:<iss_user_id>:<collection>` for member caps. `"self"` is added by the route-builder when `params["identity"] == auth.identity`.

```python
from starfish_server import (
    create_cap_cert_role_resolver,
    create_in_memory_nonce_cache,
    create_in_memory_revocation_store,
    CapAuthError,
    NonceCache,
    RevocationStore,
    RevocationList,
    RevocationEntry,
)
```

`create_in_memory_nonce_cache` and `create_in_memory_revocation_store` are development-grade; for multi-process deployments you implement the `NonceCache` / `RevocationStore` protocols against a shared backend (Redis, SQL, etc.).

`CapAuthError` is raised for surfaceable 4xx auth failures (`401`, `403`).

Anonymous mode: `allow_anonymous=True` (default) returns `AuthResult(identity="", roles=["public"])` when the `Authorization` header is missing or empty, so collections gated by `read_roles=["public"]` keep working.

### Required request headers (cap-cert auth)

| Header | Value |
|---|---|
| `Authorization` | `Cap <base64(stable_stringify(cap))>` |
| `X-Starfish-Sig` | base64 Ed25519 signature over `request_signing_canonical_input` |
| `X-Starfish-Ts` | Unix milliseconds (±5 min server clock skew) |
| `X-Starfish-Nonce` | base64 random 16 bytes — server-side LRU prevents reuse |

The matching client wiring is in [`starfish-sdk`](../client/README.md) via the `CapProvider` protocol.

### Keeping a custom resolver

The `role_resolver` extension point is preserved. Any async callable matching `(request) -> AuthResult` is acceptable — useful when tying Starfish identities to an existing OAuth provider, mTLS, or service-mesh JWTs. The cap-cert resolver is the **default**, not the only option.

## Collection config

```python
from starfish_server import SyncConfig, CollectionConfig, EncryptionMode
```

The relevant v3 fields on `CollectionConfig`:

| Field | Type | Notes |
|---|---|---|
| `encryption` | `"none"` or `"delegated"` | Two modes only. |
| `keyring_path` | `str \| None` | Override for the keyring document path. Defaults to `<storage_path>/_keyring`. Only relevant for `"delegated"`. |
| `read_roles` / `write_roles` | `list[str]` | Match against either resolver roles (e.g. `cap:read:notes`, `delegated:<userId>:notes`) or enricher roles (e.g. `team-member`). |
| `root_only` | `bool \| None` | Restrict to the **root device** (a self-signed device cap, `iss == sub`); paired devices and member caps get `403`. Incompatible with a `"public"` read/write role (rejected at config load). See [Root-only collections](#root-only-collections). |

### Path-scope rules

Scope `paths` entries are globs against `<collection>/<rest>`. `*` matches any run of non-slash characters; `**` matches across slashes. A leading `!` is a denylist — explicit deny beats wildcard allow. Substitutions: `{identity}` resolves to `auth.identity` before matching.

For `kind: "member"` caps, the resolver verifies (after substitution) that no scope path enters the issuer's `users/<iss_user_id>/*` namespace — a member cap cannot be used to escalate into the issuer's private data.

### Rate limiting

A collection's `rateLimit` supports independent **per-action** rules — `push`, `pull`, and `list` — each with its own `windowMs`, `maxRequests`, and `bucket` mode, and each with its own counter:

```python
rateLimit={
    "push": {"windowMs": 3_600_000, "maxRequests": 10, "bucket": "ip"},  # 10 push / hour / ip
    "pull": {"windowMs": 60_000, "maxRequests": 1000},                   # bucket: "identity" (default)
    "list": {"maxRequests": 50},                                         # window inherited from global rateLimit
}
```

`bucket` is `"identity"` (default — per authenticated caller, falling back to `X-Forwarded-For` / socket IP / anonymous), `"ip"` (strictly per IP), or `"identity+ip"` (one budget per `(identity, ip)` pair). For defense-in-depth, a rule can instead declare `identity` and/or `ip` sub-limits — independent counters, rejected if *either* trips ("≤N per identity AND ≤M per ip"). The legacy flat form `{"windowMs", "maxRequests"}` still limits `push` only. Limiting is in-memory per process by default; pass a shared `KVAdapter` as `rate_limit_store` (e.g. `create_k2v_adapter` over Garage K2V) to enforce limits across instances, and `create_kv_nonce_cache(kv)` for distributed replay protection. The Python server uses the real socket IP, so IP-based modes are reliable. See [docs/ts/server/rate-limiting.md](../../../docs/ts/server/rate-limiting.md).

## Public surface (selected)

```python
# Auth (v3)
from starfish_server import (
    create_cap_cert_role_resolver, CapAuthError,
    create_in_memory_nonce_cache, NonceCache,
    create_in_memory_revocation_store, RevocationStore, RevocationList, RevocationEntry,
)

# Storage
from starfish_server import (
    AbstractObjectStore, StoreContext,
    MemoryObjectStore, CustomObjectStore,
    FilesystemObjectStore, FilesystemStorageOptions,
)
# S3 lives in starfish_server.storage.s3 (optional dependency).

# Enrichers
from starfish_server import (
    create_entitlement_role_enricher, EntitlementRoleEnricherOptions,
    compose_enrichers,
)

# Config
from starfish_server import (
    SyncConfig, CollectionConfig, NamespaceConfig, RemoteConfig,
    QueueConfig, CollectionRateLimitConfig, RateLimitConfig,
    EncryptionMode, WriteMode, SyncTrigger, FieldPermission,
    ConfigEndpointOptions,
    validate_config, parse_config_json, load_config, save_config, load_config_file,
)

# Errors / constants
from starfish_server import (
    StartupError, AuthError, ConflictError, NotFoundError,
    ROLE_PUBLIC, ROLE_SELF, OP_READ, OP_WRITE,
    ENCRYPTION_NONE, ENCRYPTION_DELEGATED, ...,
)
```

## Composing with enrichers

`create_cap_cert_role_resolver` produces the baseline role set. `role_enricher` layers application-level roles on top — team membership, feature entitlements, custom RBAC. Both kinds of role match against `read_roles` / `write_roles`. (Starfish no longer ships a group-membership enricher; write your own — it's a few lines — or use member caps from `starfish-sharing`.)

```python
from starfish_server import (
    create_cap_cert_role_resolver,
    compose_enrichers,
)
from starfish_server.router import create_sync_router, SyncRouterOptions

# Bring your own application-level enricher.
async def team_enricher(auth, params):
    if await is_team_member(auth.identity, params.get("teamId")):
        return ["team-member"]
    return []

router = create_sync_router(SyncRouterOptions(
    store=store,
    config=config,
    role_resolver=create_cap_cert_role_resolver(
        nonce_cache=nonce_cache,
        revocation_store=revocation_store,
        plugins=plugins,
    ),
    role_enricher=compose_enrichers(team_enricher),
))
```

Full pattern catalog: [docs/ts/server/group-access.md](../../../docs/ts/server/group-access.md), [docs/ts/server/entitlements.md](../../../docs/ts/server/entitlements.md).

## Root-only collections

Set `root_only=True` on a `CollectionConfig` to restrict it to the **root device** (a
self-signed device cap, `iss == sub`). Paired/provisioned device caps and member caps are
rejected with `403` — on standalone pull/list/push and on bundle pulls — in addition to the
collection's normal `read_roles` / `write_roles`. Combining `root_only` with a `"public"`
role is rejected at config load. The predicate is `is_root_device_cap` (in
`starfish_protocol`, re-exported from `starfish_identities`), surfaced as the
`ROLE_ROOT_DEVICE` role. See
[docs/ts/server/root-only-collections.md](../../../docs/ts/server/root-only-collections.md).

## Removed in v3.0

| Symbol | Replacement |
|---|---|
| `EncryptedObjectStore` | `encryption="delegated"` (client-side keyring) |
| `encryption_secret`, `server_encryption_secret`, `server_identity`, `identity_encryption_info`, `server_encryption_info` | n/a — server no longer holds keys |
| `signature_verifier` | `create_cap_cert_role_resolver` |
| `CollectionConfig.client_encrypted` | `encryption="delegated"` |
| `CollectionConfig.public_key` | n/a — public keys live in the keyring document |
| `create_group_role_enricher`, `GroupRoleEnricherOptions` | member caps (`starfish-sharing`), or your own `RoleEnricher` for list-based RBAC |

Migration runbook: [docs/migration/v2-to-v3.md](../../../docs/migration/v2-to-v3.md).

## Development

```bash
uv sync
uv run pytest -v
```
