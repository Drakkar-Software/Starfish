# @drakkar.software/starfish-replica

Replication extension for [Starfish](https://github.com/Drakkar-Software/starfish). Lets you run
multiple Starfish servers that stay in sync: a **primary** holds the source of truth; **replicas**
pull from it and serve reads locally.

Shipped as a `ServerPlugin` — it owns its own config (the `remote` field is no longer part of the
core `CollectionConfig`).

## Install

```bash
pnpm add @drakkar.software/starfish-replica
```

## Usage

```ts
import { createSyncRouter } from "@drakkar.software/starfish-server"
import { createReplicaServerPlugin } from "@drakkar.software/starfish-replica"

const replica = createReplicaServerPlugin({
  store,
  syncConfig: config,
  collections: {
    // keyed by root collection name
    posts: {
      url: "https://primary.example.com/v1",
      pullPath: "/pull/posts/featured",
      intervalMs: 60_000,
      headers: { Authorization: "Bearer <replica-token>" },
      writeMode: "pull_only",        // clients can't push to this replica
      syncTriggers: ["scheduled"],   // or ["on_pull"]
    },
  },
})

const router = createSyncRouter({
  store,
  config,
  roleResolver,
  plugins: [replica /*, ...other plugins */],
})

replica.manager.start() // begin scheduled / initial syncs
```

Register `replica.shutdown` via the server's graceful shutdown (it stops the sync timers) — passing
the plugin in `plugins` to `createGracefulShutdown` handles this automatically.

## Write modes

| Mode | Client reads | Client writes | Syncs from primary |
| --- | --- | --- | --- |
| `pull_only` | ✓ | rejected (405) | ✓ replace |
| `push_through` | ✓ | forwarded to primary | ✓ replace |
| `bidirectional` | ✓ | stored locally | ✓ merge (remote-wins) |
| `push_only` | rejected (405) | stored locally | — |

`push_through` and `bidirectional` require `pushPath`.

## Authenticated replicas (`createReplicaAuth`)

When the primary requires cap-cert + Ed25519 request signing, build a signing
`fetch` wrapper with `createReplicaAuth` and inject it into the manager via
`fetchFn`. It signs every outgoing pull/push request and attaches the cap +
signature headers:

```ts
import { createReplicaAuth, ReplicaManager } from "@drakkar.software/starfish-replica"

const auth = await createReplicaAuth({ passphrase: PLATFORM_PASSPHRASE })
// Optional: cross-check the derived identity before trusting it.
if (auth.userId !== expectedUserId) throw new Error("identity mismatch")

const manager = new ReplicaManager(store, collections, { fetchFn: auth.fetch })
```

Per request it bootstraps (once) a self-signed device cap-cert from the
passphrase — or accepts a pre-bootstrapped `credentials: DeviceCredentials` — then
attaches:

| Header | Value |
| --- | --- |
| `Authorization` | `Cap ` + base64(stableStringify(cap-cert)) |
| `X-Starfish-Sig` | base64 Ed25519 signature over the canonical request bytes |
| `X-Starfish-Ts` | Unix milliseconds |
| `X-Starfish-Nonce` | base64 16-byte random nonce |

The cap-cert has a finite TTL (30 days by default). `createReplicaAuth` re-mints
it transparently when it nears expiry (`refreshMarginSec`, default one day) so a
long-uptime replica never 401-storms — the signing key and userId are preserved
across refreshes. `scope` defaults to `scopes.rootAll()`; pass a narrower
`ScopePreset` to restrict the cap.

See `docs/ts/replica/01-overview.md` for the full guide.

## A second data path: mirroring into a Starfish space (`./space`)

Everything above replicates a primary→replica-*server* HTTP pull into a local
`starfish-server` `ObjectStore`. This subpath drives an entirely different
kind of channel: mirroring a local data source (a mobile app's own store, a
node's local state) into per-collection nodes of one or more Starfish
spaces, encrypted under each space's own keyring.

The `ReplicaManager` exported from `./space` is a DIFFERENT class than the
root `.` entry's `ReplicaManager` — this one is pure scheduler (no HTTP back-
compat constructor), so importing it never pulls in `starfish-server`; safe
to bundle into a mobile or browser client.

```bash
pnpm add @drakkar.software/starfish-replica @drakkar.software/starfish-spaces
```

```ts
import { createSpaceMirrorChannel, ReplicaManager } from "@drakkar.software/starfish-replica/space"

const channel = createSpaceMirrorChannel({
  name: "cloud-mirror",
  session, // a starfish-spaces Session
  collections: [
    { id: "user-accounts", spaceName: "app-mirror" }, // tier defaults to "private"
    { id: "user-settings", spaceName: "app-mirror-private", tier: "private" },
    { id: "public-profile", spaceName: "app-mirror", tier: "public" },
  ],
  enabledIds: () => currentlyEnabledCollectionIds(), // read fresh every sync
  readSource: (id) => readLocalCollection(id),
  docPath: (collectionId, spaceId, nodeId) => `spaces/${spaceId}/objects/mirror/${nodeId}`,
  title: (collectionId) => COLLECTION_TITLES[collectionId] ?? collectionId, // optional
})

const manager = new ReplicaManager([
  { channel, schedule: { triggers: ["scheduled"], intervalMs: 5 * 60_000 } },
])
manager.start()

// ... later, read the most recent sync's result:
channel.result // { spaces, created, written, skipped, cleared, failed }
```

Read side (session-less, for a third party holding a read-only member cap
into the space — e.g. `starfish-spaces`' `inviteToSpace`):

```ts
import { readSpaceMirror } from "@drakkar.software/starfish-replica/space"

const collections = await readSpaceMirror({
  rendezvous: { baseUrl, namespace },
  spaceId,
  cap, // the minted member cap
  devEdPrivHex,
  devKemPrivHex,
  isKnownCollection: (type) => KNOWN_IDS.has(type),
  // Same signature as the writer's, so ONE template can be shared. On this
  // side the collection id is the node's `type`.
  docPath: (collectionId, spaceId, nodeId) => `spaces/${spaceId}/objects/mirror/${nodeId}`,
})
```

The keyring is pulled LAZILY — only once a node's document actually comes back
carrying `_encrypted`. A space whose every collection is written at
`tier: "public"` never mints a keyring at all, and this reader reads it in full
without one.

Public read side (no grant, no cap, no keyring — for the collections written
with `tier: "public"`):

```ts
import { readPublicSpaceMirror } from "@drakkar.software/starfish-replica/space"

const published = await readPublicSpaceMirror({
  rendezvous: { baseUrl, namespace },
  spaceId,
  // Optional. Omit to enumerate the world-readable public object directory
  // instead — an anonymous caller cannot list a space's nodes itself.
  nodes: [{ id: nodeId, type: "public-strategy" }],
  isKnownCollection: (type) => KNOWN_IDS.has(type), // optional, default: all
  docPath: (collectionId, spaceId, nodeId) => `spaces/${spaceId}/objects/pub/${nodeId}`,
})
```

Notes:

- `readPublicSpaceMirror` builds an ANONYMOUS client (`starfish-spaces`'
  `makeAnonSpaceClient`) and holds no cap and no keyring, which is the whole
  point of the public tier: anyone with the space id reads what its owner chose
  to publish, with no invite in between. The trade-off is that it cannot
  enumerate the space — the object index is `space:member` — so it needs either
  explicit `nodes` (`{ id, type }`, e.g. carried by a share link) or the
  world-readable public object directory (`_index/objects/{shard}`,
  `directoryShard` defaults to `"public"`), which the server projects from
  `objindex` writes and which by construction lists only `access: "public"`
  nodes. Its result is keyed exactly like `readSpaceMirror`'s: collection id
  (the node's `type`) to plaintext document.
- A node whose document unexpectedly carries `_encrypted` is OMITTED from that
  result rather than returned — returning the sealed envelope would hand you
  ciphertext you would go on to treat as data. It is omitted rather than thrown
  on because the state is reachable with nothing broken: a `public` ->
  `private` flip writes the encrypted content before patching the node's stored
  access, so for that window the directory still advertises a node whose
  content is already sealed. One such node must not cost every other published
  collection its read. A failed DIRECTORY pull, on the other hand, does throw:
  "the server is unreachable" must not look the same as "this space publishes
  nothing".

- Each collection picks a storage `tier`, defaulting to `"private"`:
  `"private"` resolves to the channel-wide `nodeEnc` — itself
  `{ access: "space", enc: true }` unless you overrode it (readable only by
  space members, sealed under the space's keyring) — and `"public"` resolves
  to `{ access: "public", enc: false }` always, ignoring `nodeEnc`
  (world-readable plaintext at its storage URL). It is a closed enum rather
  than a raw `{ access, enc }` pair on purpose: the server rejects
  `access:"public"` with `enc:true`, and an enum makes that combination
  unrepresentable instead of a failure discovered at `createNode`, after a
  space has already been created. Writing `tier: "private"` out is exactly
  equivalent to omitting it, so spelling out the default never costs you a
  `nodeEnc` override, and nothing configured before tiers existed changes
  behavior.
- Flipping a collection's tier is safe, INCLUDING across a restart. The
  channel compares the node's STORED `access`/`enc` (recorded in the space's
  object index, so they outlive the process) against the tier it is configured
  for now; when they differ it clears the node's content under the STORED axes
  before writing under the new ones — otherwise a `public` -> `private` flip
  leaves the old plaintext sitting at a world-readable URL, which is the case
  that matters, since a user toggling the setting usually does restart the app
  before the next sync. Once the new content is written, the node's STORED axes
  are PATCHED to the new tier (`SpacePort.setNodeAccess`), in that order:
  patching before the write would leave the index claiming a tier the stored
  content does not match if the write then failed. That patch is not
  bookkeeping. The object index is projected into a world-readable index of
  every `access: "public"` node's id, title and type, so a node left recorded
  as public keeps being advertised to anonymous callers even after its content
  is cleared, contradicting the setting the user just changed. It is also what
  makes the flip self-limiting: without it the stored axes read as the old tier
  every cycle, so the clear re-fires forever and a `"source-hash"` collection
  that flipped once could never skip again. The patch normalizes exactly the
  way `createNode` does (no `access` for `"space"`, no `enc` when false), so a
  patched node is indistinguishable from one born at that tier, and a patch
  that fails is isolated like any other per-collection failure. The
  `"source-hash"` skip is keyed by tier so the migrating write is never
  mistaken for an unchanged one — a tier change does not alter what
  `readSource` returns.
- A `public` collection's clear is never skipped, even on a channel instance
  that already cleared it in an earlier cycle. The redundant no-op CAS write
  is cheap; being wrong about a public clear leaves world-readable data.
- `changeDetection` defaults to `"none"` — every enabled collection is
  written unconditionally every cycle, matching a hand-rolled writer's usual
  behavior. Opt into `"source-hash"` only when this channel is the SOLE
  writer of a node; a second writer (e.g. a mobile device AND a node both
  writing the same mirror) would silently diverge from what a hash-skip
  assumes is already there.
- A failing collection is isolated: if one collection's write or clear throws
  (an oversized document, a CAS 409 that exhausted its retries, a network
  blip), the other collections — and the other spaces — still sync, and the
  failing ids land in `result.failed`. A whole space failing contributes every
  collection routed to it. The errors are not swallowed: `sync()` still
  rejects with an `AggregateError` naming the failed ids, but only after the
  cycle has run and `channel.result` has been replaced, so the scheduler's
  `onError` handler sees the failure while `result` still describes what
  actually got written.
- `ReplicaCallContext.callKind` (`"replicator"` vs `"classic"`) is threaded
  into `readSource` unchanged, so one shared data-access function can serve
  both a scheduler-driven sync and a direct app call without the channel or
  manager needing to know why it was invoked.
- `@drakkar.software/starfish-spaces`, `starfish-client`, and
  `starfish-keyring` are optional peer dependencies — only importing
  `@drakkar.software/starfish-replica/space` pulls them in; the root `.`
  entry (and `HttpReplicaChannel`) never does.
