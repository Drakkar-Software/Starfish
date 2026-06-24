---
sidebar_position: 6
---

# Rate Limiting

Starfish can rate-limit requests per collection and **per action** (`push` / `pull` /
`list`), each with its own window, request cap, and bucketing strategy. Limiting is
in-memory and per server process.

## Config shape

Rate limiting is configured under a collection's `rateLimit` field, with optional global
defaults under the top-level `SyncConfig.rateLimit`.

```ts
const config: SyncConfig = {
  version: 1,
  // Global defaults — inherited by any rule that omits windowMs/maxRequests.
  rateLimit: { windowMs: 60_000, maxRequests: 100 },
  collections: [
    {
      name: "events",
      storagePath: "events/{identity}/{day}",
      readRoles: ["self"], writeRoles: ["self"],
      encryption: "none", maxBodyBytes: 65_536, allowedMimeTypes: ["application/json"],
      rateLimit: {
        // 10 pushes per hour, bucketed per IP
        push: { windowMs: 3_600_000, maxRequests: 10, bucket: "ip" },
        // 1000 pulls per minute, bucketed per authenticated identity (default)
        pull: { windowMs: 60_000, maxRequests: 1000 },
        // list inherits windowMs/maxRequests from the global rateLimit
        list: { maxRequests: 50 },
      },
    },
  ],
}
```

### Per-action rules

| Field | Notes |
|---|---|
| `push` / `pull` / `list` | A `RateLimitRule` for that action. Each action keeps its **own counter** — exhausting `push` never throttles `pull`. An action with no rule is unmetered. |
| `windowMs` | Window length in ms. Falls back to the flat collection field, then the global `rateLimit`. |
| `maxRequests` | Max requests per window. Same fallback chain. |
| `bucket` | `"identity"` (default) or `"ip"`. See below. |

### Bucket modes (single counter)

A rule with `windowMs` / `maxRequests` keeps one counter, keyed by its `bucket` mode:

- **`"identity"`** (default) — bucket by the authenticated caller, falling back to the
  first `X-Forwarded-For` hop, then the client IP, then a shared `"anonymous"` bucket.
  This is fair per-caller limiting.
- **`"ip"`** — bucket strictly by IP, ignoring identity. Use this for a literal
  "N requests per hour per IP" limit regardless of who is authenticated.
- **`"identity+ip"`** — bucket by the `(identity, ip)` pair. One budget per distinct
  combination: the same person from two IPs gets two independent budgets, and two people
  behind one IP get independent budgets too.

### Two independent limits (per-identity *and* per-ip)

Instead of `bucket`, a rule may declare an `identity` and/or `ip` sub-limit. Each is its
own counter, and a request is rejected if **either** dimension is over budget — the classic
"≤N per user **and** ≤M per IP" defense-in-depth pattern. Each dimension can set its own
`windowMs` / `maxRequests` (inheriting from the rule, then flat, then global):

```ts
rateLimit: {
  push: {
    identity: { windowMs: 3_600_000, maxRequests: 100 },  // ≤100/hour per identity
    ip:       { windowMs: 3_600_000, maxRequests: 1000 }, // AND ≤1000/hour per ip
  },
}
```

A rule may use **either** `bucket` **or** the `identity`/`ip` sub-limits, not both
(rejected at config load).

> **TypeScript / Hono caveat:** the TS server has no portable socket IP, so any IP-dependent
> bucketing (`bucket: "ip"`, `bucket: "identity+ip"`, or an `ip` sub-limit) keys by the first
> `X-Forwarded-For` hop only. **Without that header, the ip part collapses to a shared
> `"anonymous"` bucket** — a per-IP limit silently becomes a global one. Always run the TS
> server behind a proxy that sets `X-Forwarded-For`. (The config loader emits a warning when
> IP-based bucketing is configured.) The Python server uses the real socket IP, so IP-based
> modes are reliable there.

## Backward compatibility

The legacy flat form is still honored and unchanged:

```ts
rateLimit: { windowMs: 60_000, maxRequests: 100 }   // limits PUSH only
```

Flat `windowMs` / `maxRequests` are treated as an implicit `push` rule and, as before,
require a global `rateLimit` to be set. `pull` and `list` stay **unmetered** unless you add
an explicit rule for them — so adding per-action limits never silently throttles reads on an
existing deployment.

## Enforcement model

By default, counters are held in an in-memory map per server process (bounded, with
oldest-bucket eviction under a flood of distinct keys). Across a horizontally-scaled
deployment, each instance enforces its own counts, so limits are **approximate** — an
effective cap of roughly `maxRequests × instances`.

### Sharing counters across instances (`KVAdapter`)

Pass a shared `KVAdapter` as `rateLimitStore` (TS `SyncRouterOptions`) /
`rate_limit_store` (Python `SyncRouterOptions`) to enforce limits across instances.
Counters are namespaced per collection/action/dimension automatically.

```ts
import { createSyncRouter, createK2VAdapter, createFetchK2VTransport } from "@drakkar.software/starfish-server"

const kv = createK2VAdapter({
  transport: createFetchK2VTransport({ endpoint: "https://garage.example", bucket: "starfish", signRequest }),
})
const app = createSyncRouter({ store, config, roleResolver, rateLimitStore: kv })
```

The same `KVAdapter` also backs the **nonce cache** for distributed replay protection —
build it with `createKvNonceCache(kv)` and pass it to your cap-cert resolver.

### Garage K2V caveats

[Garage K2V](https://garagehq.deuxfleurs.fr/documentation/reference-manual/k2v/) has no
compare-and-set, no atomic increment, and no native key expiry — concurrent writes become
"siblings" merged by the reader via a causality token. The `createK2VAdapter` backend
therefore:

- embeds an expiry in each value and treats expired-on-read entries as absent (logically
  expired keys linger until overwritten or externally pruned — there is no TTL);
- **sums** live siblings on `increment`, so concurrent increments may briefly **overcount**
  (a stricter, fail-closed limit) — never undercount;
- does best-effort read-then-write for the nonce cache: two *concurrent* requests with the
  *same* nonce can both be accepted (a narrow replay window). This still closes the common
  replay case and beats per-node caching; use a CAS-capable store (e.g. Redis) to close the
  concurrent-duplicate window completely.

`createK2VAdapter` takes an injectable transport (the HTTP/auth boundary); `createFetchK2VTransport`
provides a `fetch`-based one with an optional `signRequest` hook for AWS SigV4 / proxy auth.

## Validation

Config load rejects:

- a non-positive `windowMs` / `maxRequests`,
- an invalid `bucket` value (must be `"identity"`, `"ip"`, or `"identity+ip"`),
- a rule that sets both `bucket` and an `identity`/`ip` sub-limit,
- an explicit `push` / `pull` / `list` rule (or, in the two-independent form, any
  `identity`/`ip` dimension) that cannot resolve both `windowMs` and `maxRequests` from
  the dimension, the rule, the flat collection fields, or the global `rateLimit`.
