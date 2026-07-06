# @drakkar.software/starfish-spaces

Starfish extension for **multi-user spaces**: a roster of members, a shared object
tree with per-node access control and optional E2EE, invite / link join flows,
revocation, and a sealed request/grant inbox round-trip.

Mirrors [`starfish-spaces`](../python/spaces) (Python).

## Install

```bash
npm install @drakkar.software/starfish-spaces
```

## Concepts

| Concept | Description |
|---|---|
| **Space** | Named container with owner + member roster at `spaces/{spaceId}/_access`. |
| **Node** | Entry in a space's object tree with `access` (`'public'` \| `'space'` \| `'invite'`) and `enc` (boolean). |
| **SpaceLayout** | Protocol that produces all storage paths and cap scopes. Inject a custom layout or use `defaultSpaceLayout`. |
| **Session** | Central runtime object: identity keys + Starfish clients + resolved layout. |
| **Space keyring** | One AES-256-GCM keyring per space encrypts all `enc` nodes. |
| **Inbox** | Monthly-sharded public-write ring buffer for sealed resource requests. |

## Quick start

```ts
import { buildSession, makeSpaceClient, defaultSpaceLayout } from "@drakkar.software/starfish-spaces"

const session = await buildSession({
  passphrase: "…",
  serverUrl: "https://sync.example.com",
  layout: defaultSpaceLayout(),
})

const client = makeSpaceClient(session)

// Create a space
const spaceId = await client.registry.createSpace({ name: "My Space" })

// Invite a member
await client.members.invite(spaceId, { userId: recipientId, write: true })
```

## Invite links (single-link join)

`createSpaceInviteLink` produces a **bearer link** — the ephemeral member credential
rides in the URL fragment (`{origin}/join#…`), so anyone holding the link can join
with no request/grant round-trip. It is the right tool for owner-initiated sharing to
a trusted recipient (not for public "request access", which is the sealed inbox flow).

```ts
// Owner: mint a link that expires in 24h.
const { link, inviteUserId } = await createSpaceInviteLink(
  session, spaceId, "My Space", /* write */ true, origin,
  { ttlSec: 24 * 3600 },              // or { expiresAt: <unix seconds> }; omit → 30-day default
)

// Invitee: redeem it (rejects an expired / not-yet-valid link up front).
await joinSpaceByLink(session, decodeSpaceInviteLink(fragment))

// Owner: revoke this ONE link later, using the returned handle.
await revokeSpaceAccess(session, spaceId, inviteUserId, { generation, submitRevocation })
```

- **Expiry** — `ttlSec` / `expiresAt` bound the cap's `exp`; the server enforces `nbf`/`exp`
  on every request, so a lapsed link genuinely stops working. Default is 30 days.
- **Per-link revocation** — each call mints a *distinct* ephemeral member, so revoking one
  link (via its `inviteUserId`) never affects other members or links.
- **Multi-use** — bearer links are inherently reusable: there is **no** client-only single-use,
  because the secret lives entirely in the fragment and the server counts no redemptions. Use a
  short `ttlSec` and/or revoke after the intended join.

## API surface

- **`buildSession` / `deriveSession`** — construct the runtime session from passphrase or device keys
- **`makeSpaceClient`** — unified client covering registry, members, nodes, objects, inbox, identity links
- **`configureSpaces` / `defaultSpaceLayout`** — layout injection
- **`generateSeedWords` / `isValidSeed`** — BIP-39 mnemonic helpers
- **`createPrefsStore`** — generic per-identity preference store on the `_spaces` registry `extra`-field (cache + subscriptions + KV persistence + CAS-safe synced write); write-through or debounced from one config
- **`startDevicePairing` / `completeDevicePairing`** — device-pairing rendezvous over the public `_pairing/<nonce>` slot (hash-guarded push, slot clear, mandatory root pinning)
- **`appendToInbox`** — append a (pre-sealed) element to an identity's public inbox shard, authored by the session identity
- **`cacheProfile` / `loadCachedProfile` / `readProfileCached`** — public-profile offline cache over the configured `kvAdapter`
- **`createSpacesServerPlugin`** — server-side companion (server plugin for object-index projection)

See the [full guide](/extensions/spaces) for detailed documentation on all subsystems.
