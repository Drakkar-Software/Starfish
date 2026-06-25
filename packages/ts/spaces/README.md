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

## API surface

- **`buildSession` / `deriveSession`** — construct the runtime session from passphrase or device keys
- **`makeSpaceClient`** — unified client covering registry, members, nodes, objects, inbox, identity links
- **`configureSpaces` / `defaultSpaceLayout`** — layout injection
- **`generateSeedWords` / `isValidSeed`** — BIP-39 mnemonic helpers
- **`createSpacesServerPlugin`** — server-side companion (server plugin for object-index projection)

See the [full guide](/extensions/spaces) for detailed documentation on all subsystems.
