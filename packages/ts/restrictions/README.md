# @drakkar.software/starfish-restrictions

Starfish identity action restrictions extension — deny access for a list of identities, scoped to the
whole server, a namespace, a collection, or a single action (`pull` / `push` / `list`). Identity lists
are static arrays or callbacks, and may also be declared statically in the serializable `SyncConfig`.

Unlike roles and cap scopes (which *grant* access), restrictions *remove* it: a `deny` rule blocks the
listed identities; an `allow` rule permits only the listed identities. The plugin contributes an
`authorize` hook that runs at the server's central authorization gate, so it covers every action
including `list`, batch pulls, and bundle members.

## Install

```sh
pnpm add @drakkar.software/starfish-server @drakkar.software/starfish-restrictions
```

## Usage

```ts
import { createSyncRouter, defaultServerPlugin } from "@drakkar.software/starfish-server"
import { createRestrictionsPlugin } from "@drakkar.software/starfish-restrictions"

const router = createSyncRouter({
  store,
  config,
  roleResolver,
  plugins: [
    defaultServerPlugin,
    createRestrictionsPlugin({
      // enforce static `restrictions` declared in the config
      config,
      // plus runtime rules (static arrays or callbacks)
      rules: [
        { mode: "deny", identities: ["evil-user"] }, // server-wide
        {
          mode: "deny",
          identities: async (ctx) => loadBannedUsers(ctx.collection),
          scope: { collection: "notes", action: "push" },
        },
        { mode: "allow", identities: ["alice", "bob"], scope: { namespace: "acme" } },
      ],
    }),
  ],
})
```

## Static config

Declare restrictions directly in the JSON-serializable config at the server, namespace, or collection
level (callbacks are not allowed in config — use `rules` for those):

```ts
const config = {
  version: 1,
  restrictions: [{ mode: "deny", identities: ["globally-banned"] }],
  collections: [
    {
      name: "notes",
      // …
      restrictions: [{ mode: "deny", identities: ["spammer"], actions: ["push"] }],
    },
  ],
}
```

Pass that `config` to `createRestrictionsPlugin({ config })`. **Static restrictions are inert unless
this plugin is installed** — `createSyncRouter` logs a warning if a config declares `restrictions`
but no `authorize`-hook plugin is wired.

## Evaluation

- **Deny wins.** If any applicable `deny` rule lists the caller, the request is rejected.
- Otherwise the caller must be listed in **every** applicable `allow` rule.
- Anonymous callers never match a `deny` list, and never satisfy an `allow` list (so `allow` blocks
  anonymous access).

Rejections return `403 { "error": "identity restricted" }` (override via `status` / `error`).

See `docs/ts/server/identity-restrictions.md` for the full guide.
