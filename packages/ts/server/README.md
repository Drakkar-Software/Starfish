# @drakkar.software/starfish-server

TypeScript server for [Starfish](../../../README.md). Hono-based, compatible with Cloudflare Workers, Node, and Bun.

## Install

```bash
pnpm add @drakkar.software/starfish-server @drakkar.software/starfish-protocol hono
```

Optional storage adapters: `npm install @aws-sdk/client-s3` (for `S3ObjectStore`).

## What's in v3.0

Starfish 3.0 removes server-held encryption entirely. The two encryption modes are:

```ts
export type EncryptionMode = "none" | "delegated"
```

- `"none"` — server stores plaintext.
- `"delegated"` — server stores opaque `{_encrypted, _epoch}` ciphertext and a plaintext keyring document at `<storagePath>/_keyring` (or the explicit `keyringPath`). The server never sees a CEK.

The v2 `"identity"`, `"server"`, and `"group"` modes are gone. So are the `encryptionSecret`, `serverEncryptionSecret`, `serverIdentity`, `identityEncryptionInfo`, `serverEncryptionInfo`, `signatureVerifier`, `EncryptedObjectStore`, `clientEncrypted`, and `publicKey` symbols. See [docs/migration/v2-to-v3.md](../../../docs/migration/v2-to-v3.md).

## Quickstart (v3)

```ts
import { Hono } from "hono"
import {
  createSyncRouter,
  MemoryObjectStore,
  parseConfigJson,
  createCapCertRoleResolver,
  createInMemoryNonceCache,
  createInMemoryRevocationStore,
} from "@drakkar.software/starfish-server"

const store = new MemoryObjectStore(new Map())

const config = parseConfigJson(JSON.stringify({
  version: 1,
  collections: [
    {
      name: "notes",
      storagePath: "notes/{identity}",
      readRoles:  ["cap:read:notes", "self"],
      writeRoles: ["cap:write:notes", "self"],
      encryption: "delegated",
      maxBodyBytes: 65_536,
      // keyringPath defaults to `notes/_keyring`
    },
  ],
}))

const sync = createSyncRouter({
  store,
  config,
  roleResolver: createCapCertRoleResolver({
    nonceCache: createInMemoryNonceCache(),
    revocationStore: createInMemoryRevocationStore(),
    allowAnonymous: true,
  }),
})

const app = new Hono()
app.route("/v1", sync)
export default app
```

## Cap-cert auth

`createCapCertRoleResolver` is the v3 default `RoleResolver`. For every authenticated request it:

1. Parses `Authorization: Cap <base64(stableStringify(cap))>`.
2. Verifies the cap-cert (signature, `nbf`/`exp` ± skew, `userId` derivation, kind-specific well-formedness).
3. Verifies the per-request signature using `X-Starfish-Sig` / `X-Starfish-Ts` / `X-Starfish-Nonce`.
4. Checks the nonce against an LRU cache (replay protection) and the timestamp against a ±5 min clock skew.
5. Consults the `RevocationStore` for the cap's `nonce` and (for member caps) the subject.
6. Binds `auth.identity` per `kind`: `device` → `issUserId`, `member` → `subUserId`.
7. Synthesizes roles: `cap:<op>:<collection>` for each (op, collection) pair; `delegated:<issUserId>:<collection>` for member caps. `"self"` is added by the route-builder when `params.identity === auth.identity`.

```ts
import {
  createCapCertRoleResolver,
  createInMemoryNonceCache,
  createInMemoryRevocationStore,
  CapAuthError,
  type CapResolverOptions,
  type NonceCache,
  type RevocationStore,
  type RevocationList,
  type RevocationEntry,
} from "@drakkar.software/starfish-server"
```

`createInMemoryNonceCache` and `createInMemoryRevocationStore` are development-grade; for multi-process deployments you implement the `NonceCache` / `RevocationStore` interfaces against a shared backend (Redis, SQL, etc.).

`CapAuthError` is thrown for surfaceable 4xx auth failures (`401`, `403`).

Anonymous mode: `allowAnonymous: true` (default) returns `{ identity: "", roles: ["public"] }` when the `Authorization` header is missing or empty, so collections gated by `readRoles: ["public"]` keep working.

### Required request headers (cap-cert auth)

| Header | Value |
|---|---|
| `Authorization` | `Cap <base64(stableStringify(cap))>` |
| `X-Starfish-Sig` | base64 Ed25519 signature over `requestSigningCanonicalInput` |
| `X-Starfish-Ts` | Unix milliseconds (±5 min server clock skew) |
| `X-Starfish-Nonce` | base64 random 16 bytes — server-side LRU prevents reuse |

The matching client wiring is in [`@drakkar.software/starfish-client`](../client/README.md) via `StarfishCapProvider`.

### Keeping a custom resolver

The `roleResolver` extension point is preserved. Any function `(c: Context) => Promise<AuthResult>` is acceptable — useful when tying Starfish identities to an existing OAuth provider, mTLS, or service-mesh JWTs. The cap-cert resolver is the **default**, not the only option.

## Collection config

```ts
import type { SyncConfig, CollectionConfig, EncryptionMode } from "@drakkar.software/starfish-server"
```

The relevant v3 fields:

| Field | Type | Notes |
|---|---|---|
| `encryption` | `"none" \| "delegated"` | Two modes only. |
| `keyringPath` | `string?` | Override for the keyring document path. Defaults to `<storagePath>/_keyring`. Only relevant for `"delegated"`. |
| `readRoles` / `writeRoles` | `string[]` | Match against either resolver roles (e.g. `cap:read:notes`, `delegated:<userId>:notes`) or enricher roles (e.g. `team-member`). |

### Path-scope rules

Scope `paths` entries are globs against `<collection>/<rest>`. `*` matches any run of non-slash characters; `**` matches across slashes. A leading `!` is a denylist — explicit deny beats wildcard allow. Substitutions: `{identity}` resolves to `auth.identity` before matching.

For `kind: "member"` caps, the resolver verifies (after substitution) that no scope path enters the issuer's `users/<issUserId>/*` namespace — a member cap cannot be used to escalate into the issuer's private data.

### Rate limiting

A collection's `rateLimit` supports independent **per-action** rules — `push`, `pull`, and `list` — each with its own `windowMs`, `maxRequests`, and `bucket` mode, and each with its own counter:

```ts
rateLimit: {
  push: { windowMs: 3_600_000, maxRequests: 10, bucket: "ip" }, // 10 push / hour / ip
  pull: { windowMs: 60_000, maxRequests: 1000 },                // bucket: "identity" (default)
  list: { maxRequests: 50 },                                    // window inherited from global rateLimit
}
```

`bucket` is `"identity"` (default — per authenticated caller, falling back to `X-Forwarded-For` / IP / anonymous), `"ip"` (strictly per IP), or `"identity+ip"` (one budget per `(identity, ip)` pair). For defense-in-depth, a rule can instead declare `identity` and/or `ip` sub-limits — independent counters, rejected if *either* trips ("≤N per identity AND ≤M per ip"). The legacy flat form `{ windowMs, maxRequests }` still limits `push` only. Limiting is in-memory per process by default; pass a shared `KVAdapter` as `rateLimitStore` (e.g. `createK2VAdapter` over Garage K2V) to enforce limits across instances, and `createKvNonceCache(kv)` for distributed replay protection. **TS/Hono caveat:** IP-based bucketing relies on `X-Forwarded-For` — run behind a proxy that sets it, or all callers share one bucket. See [docs/ts/server/rate-limiting.md](../../../docs/ts/server/rate-limiting.md).

## Public surface (selected)

```ts
// Router
export {
  createSyncRouter,
  handleSyncPull, handleSyncPush,
  validatePathSegment, validateUrlNotPrivate, deepSanitize,
  checkBodyLimit, RateLimiter,
  corsMiddleware, securityHeadersMiddleware, requestTimeoutMiddleware,
  type SyncRouterOptions, type AuthResult, type RoleResolver, type RoleEnricher,
  type ConfigEndpointOptions, type CollectionClientInfo, type ConfigResponse,
}

// Auth (v3)
export {
  createCapCertRoleResolver, CapAuthError, type CapResolverOptions,
  authenticateMetaRequest, type MetaAuthOptions, type MetaRequestHeaders,
  createInMemoryNonceCache, type NonceCache, type NonceCacheOptions,
  createInMemoryRevocationStore, type RevocationStore, type RevocationList, type RevocationEntry,
}

// Events proxy (authenticated SSE)
export { createEventsProxyRouter, DEFAULT_SAFE_ID, type EventsProxyOptions }

// Storage
export {
  type ObjectStore, type StoreContext,
  MemoryObjectStore, CustomObjectStore,
}
// Filesystem and S3 live on the `/node` and `/s3` subpaths.

// Enrichers
export {
  createEntitlementRoleEnricher, type EntitlementRoleEnricherOptions,
  composeEnrichers,
  makeIdentityRoleEnricher,  // grant a fixed role to one identity
}

// Config
export type {
  SyncConfig, CollectionConfig, NamespaceConfig, RemoteConfig,
  QueueConfig, CollectionRateLimitConfig, RateLimitConfig,
  EncryptionMode, WriteMode, SyncTrigger, FieldPermission,
}
export { validateConfig, parseConfigJson, loadConfig, saveConfig }

// Misc
export { ReplicaManager }
export { createGracefulShutdown }
export { createConsoleLogger, createJsonLogger, createNoopLogger }
export { generateOpenApiSpec }

// Errors / constants
export { StartupError, AuthError, ConflictError, NotFoundError }
export { ROLE_PUBLIC, ROLE_SELF, OP_READ, OP_WRITE, ENCRYPTION_NONE, ENCRYPTION_DELEGATED, … }
```

## Composing with enrichers

`createCapCertRoleResolver` produces the baseline role set. `roleEnricher` layers application-level roles on top — team membership, feature entitlements, custom RBAC. Both kinds of role match against `readRoles` / `writeRoles`. (Starfish no longer ships a group-membership enricher; write your own — it's a few lines — or use member caps from `@drakkar.software/starfish-sharing`.)

```ts
import {
  createCapCertRoleResolver,
  composeEnrichers,
  type RoleEnricher,
} from "@drakkar.software/starfish-server"

// Bring your own application-level enricher.
const teamEnricher: RoleEnricher = async (auth, params) =>
  (await isTeamMember(auth.identity, params.teamId)) ? ["team-member"] : []

const router = createSyncRouter({
  store,
  config,
  roleResolver: createCapCertRoleResolver({ nonceCache, revocationStore, plugins }),
  roleEnricher: composeEnrichers(teamEnricher),
})
```

Full pattern catalog: [docs/ts/server/group-access.md](../../../docs/ts/server/group-access.md), [docs/ts/server/entitlements.md](../../../docs/ts/server/entitlements.md).

`makeIdentityRoleEnricher(identity, role)` is a ready-made enricher for the
common "elevate one well-known identity" case (e.g. a platform admin): it grants
`role` iff `auth.identity === identity` and `[]` otherwise.

## Authenticated SSE proxy (`/events`)

`createEventsProxyRouter(...)` builds a Hono router with a single authenticated
`GET /events` that proxies an upstream Server-Sent-Events firehose, gating each
subscribed candidate behind per-resource authorization:

```ts
import {
  createEventsProxyRouter,
  authenticateMetaRequest,
  composePluginValidators,
  DEFAULT_SAFE_ID,
} from "@drakkar.software/starfish-server"

const pluginValidators = composePluginValidators([identitiesServerPlugin, sharingServerPlugin])

const events = createEventsProxyRouter({
  // Bodyless cap-cert auth — same verify order as the sync resolver, with NO
  // scope.paths enforcement (per-resource authz is `authorize`'s job below).
  authenticate: (c) =>
    authenticateMetaRequest({
      method: "GET",
      pathAndQuery: new URL(c.req.url).pathname + new URL(c.req.url).search,
      host: new URL(c.req.url).host,
      headers: c.req.header.bind(c.req),
      nonceCache,
      revocationStore,
      pluginValidators,
    }),
  candidatesParam: "ids",                 // ?ids=a,b,c
  authorize: (identity, candidate) => isMember(identity, candidate),
  topicMapper: (c) => [`app-${c}`],        // candidate -> upstream topics
  upstreamUrl: "http://bridge:8091/events",
  maxCandidates: 256,                      // 400 over this many candidates
  maxTopics: 64,                           // silently truncate beyond this
  // publicPredicate: (c) => PUBLIC.has(c), // optional open-gate
  // maxPublicTopics: 64,                   // optional: cap public-only fan-out
  // idPattern: DEFAULT_SAFE_ID,            // ^[a-zA-Z0-9_-]+$, full match
})
```

The upstream URL always carries at least one `topic=`; when nothing is
authorized the sentinel `__none__` is substituted (firehose prevention).
`authenticateMetaRequest` is the reusable bodyless authenticator underneath —
use it directly for any meta-endpoint that needs cap-cert auth without
`scope.paths`.

## Root-only collections

Set `rootOnly: true` on a `CollectionConfig` to restrict it to the **root device** (a
self-signed device cap, `iss === sub`). Paired/provisioned device caps and member caps are
rejected with `403` — on standalone pull/list/push and on bundle pulls — in addition to the
collection's normal `readRoles` / `writeRoles`. Combining `rootOnly` with a `"public"` role
is rejected at config load. The predicate is `isRootDeviceCap` (in `starfish-protocol`,
re-exported from `starfish-identities`), surfaced as the `ROLE_ROOT_DEVICE` role. See
[docs/ts/server/root-only-collections.md](../../../docs/ts/server/root-only-collections.md).

## Removed in v3.0

| Symbol | Replacement |
|---|---|
| `EncryptedObjectStore` | `encryption: "delegated"` (client-side keyring) |
| `encryptionSecret`, `serverEncryptionSecret`, `serverIdentity`, `identityEncryptionInfo`, `serverEncryptionInfo` | n/a — server no longer holds keys |
| `signatureVerifier` | `createCapCertRoleResolver` |
| `CollectionConfig.clientEncrypted` | `encryption: "delegated"` |
| `CollectionConfig.publicKey` | n/a — public keys live in the keyring document |
| `createGroupRoleEnricher`, `GroupRoleEnricherOptions` | member caps (`@drakkar.software/starfish-sharing`), or your own `RoleEnricher` for list-based RBAC |

Migration runbook: [docs/migration/v2-to-v3.md](../../../docs/migration/v2-to-v3.md).
