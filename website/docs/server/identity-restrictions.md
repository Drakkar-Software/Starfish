---
sidebar_position: 5
---

# Identity Action Restrictions

Roles and cap-cert scopes decide what a caller **may** do. Restrictions decide
what specific identities **may not** do. Use them to ban an abusive account, lock
a collection down to an allowlist, or freeze writes for a set of users — without
re-minting caps or rewriting your role model.

Restrictions ship as the `@drakkar.software/starfish-restrictions` extension
(Python: `starfish-restrictions`). It contributes an `authorize` hook that the
server runs at its central authorization gate, so it covers **every** action —
`pull`, `push`, `list`, and each member of a batch pull or bundle pull.

> **Prerequisites:** [Group & Shared-Collection Access](/server/group-access)

## How it fits

```
Request arrives
  └─ roleResolver        → identity + roles
  └─ role check (readRoles/writeRoles, rootOnly, cap scope)  ── must pass
  └─ authorize hook      → restrictions plugin: deny by identity?  ── must pass
  └─ handler
```

Because the restriction check runs **after** the role check passes, it can only
*remove* access, never widen it. A denied request returns
`403 { "error": "identity restricted" }`.

## Install

```sh
pnpm add @drakkar.software/starfish-server @drakkar.software/starfish-restrictions
```

## Quick start

```ts
import { createSyncRouter, defaultServerPlugin } from "@drakkar.software/starfish-server"
import { createRestrictionsPlugin } from "@drakkar.software/starfish-restrictions"

const router = createSyncRouter({
  store, config, roleResolver,
  plugins: [
    defaultServerPlugin,
    createRestrictionsPlugin({
      rules: [
        // server-wide ban
        { mode: "deny", identities: ["abusive-user"] },
        // freeze writes to one collection
        { mode: "deny", identities: ["read-only-user"], scope: { collection: "notes", action: "push" } },
        // lock a namespace to an allowlist
        { mode: "allow", identities: ["alice", "bob"], scope: { namespace: "acme" } },
      ],
    }),
  ],
})
```

Python is identical in shape:

```python
from starfish_server import create_sync_router, SyncRouterOptions, default_server_plugin
from starfish_restrictions import create_restrictions_plugin, RestrictionRule, RestrictionScope

create_sync_router(SyncRouterOptions(
    store=store, config=config, role_resolver=role_resolver,
    plugins=[
        default_server_plugin,
        create_restrictions_plugin(rules=[
            RestrictionRule(mode="deny", identities=["abusive-user"]),
            RestrictionRule(mode="deny", identities=["read-only-user"],
                            scope=RestrictionScope(collection="notes", action="push")),
            RestrictionRule(mode="allow", identities=["alice", "bob"],
                            scope=RestrictionScope(namespace="acme")),
        ]),
    ],
))
```

## Scope

A rule applies to a request when each set field of its `scope` matches; an unset
field matches everything, and a rule with no scope is server-wide.

| Field        | Matches                                                            |
|--------------|-------------------------------------------------------------------|
| `action`     | `"pull"`, `"push"`, or `"list"`                                    |
| `collection` | the collection name                                               |
| `namespace`  | the namespace name; `null` (TS) / `ROOT` (Python) targets the root (un-namespaced) collections |

## Deny vs allow

- **`deny`** — the listed identities are blocked; everyone else passes.
- **`allow`** — only the listed identities pass; everyone else (including
  anonymous callers) is blocked.

When several rules apply to one request:

- **Deny wins.** If any applicable `deny` rule lists the caller, the request is
  rejected.
- Otherwise the caller must appear in **every** applicable `allow` rule (allow
  rules compose as an intersection).
- Anonymous callers (no identity) never match a `deny` list and never satisfy an
  `allow` list.

## Static identities (callback)

`identities` can be a function instead of an array — called per request with the
`AuthorizeContext` (`{ identity, action, collection, namespace, params, roles }`)
and may be async. Use it to read a denylist from a store or external service:

```ts
createRestrictionsPlugin({
  rules: [{ mode: "deny", identities: async (ctx) => loadBannedUsers(ctx.collection) }],
})
```

Keep callbacks fast and side-effect-free: the hook runs on every action,
including each member of a batch/bundle request.

## Static config

Restrictions can also live in the JSON-serializable `SyncConfig`, at the server,
namespace, or collection level (static lists only — callbacks can't serialize):

```ts
const config = {
  version: 1,
  restrictions: [{ mode: "deny", identities: ["globally-banned"] }],
  collections: [
    { name: "notes", /* … */ restrictions: [{ mode: "deny", identities: ["spammer"], actions: ["push"] }] },
  ],
}
```

Pass the config to the plugin so it compiles and enforces those rules:

```ts
createRestrictionsPlugin({ config, rules: [/* optional runtime rules too */] })
```

> **Static restrictions do nothing on their own.** They are enforced only when
> the restrictions plugin (which provides the `authorize` hook) is installed.
> `createSyncRouter` logs a warning if a config declares `restrictions` but no
> `authorize`-hook plugin is wired.

## Notes

- **Public collections.** When an `authorize` hook is installed, the server
  resolves the caller's identity even for `public` collections (which otherwise
  skip identity resolution), so restrictions apply there too. Two consequences:
  a request that *presents* a malformed / expired / revoked cap to a public
  collection now fails authentication (`401`/`403`) instead of being treated as
  anonymous; and a resolver configured to reject anonymous callers
  (`allowAnonymous: false`) will now reject anonymous reads of public
  collections. A truly anonymous request (no cap presented) is unaffected — it
  resolves to the anonymous identity and the hook sees `identity` as
  `undefined` (TS) / `None` (Python).
- **Batch & bundle pulls.** A restricted member of a bundle pull is silently
  omitted (the bundle never leaks it); a restricted member of a batch pull
  returns a per-entry `{ "error": "identity restricted" }`.
- **Not exposed to clients.** Restrictions are server-side policy and are never
  returned by `GET /config`.
- **Custom response.** Override the status/message via
  `createRestrictionsPlugin({ status, error })`.

## Next steps

- [Group & Shared-Collection Access](/server/group-access) — grant access with member caps and enrichers
- [Root-Only Collections](/server/root-only-collections) — restrict a collection to the root device
- [Config Endpoint](/server/config-endpoint) — what clients can and cannot see
