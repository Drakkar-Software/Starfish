# starfish-spaces

Starfish extension for **multi-user spaces**: a roster of members, a shared object
tree with per-node access control and optional E2EE, invite / link join flows,
revocation, and a sealed request/grant inbox round-trip.

Mirrors [`@drakkar.software/starfish-spaces`](../ts/spaces) (TypeScript).

## Install

```bash
pip install starfish-spaces
```

## Concepts

| Concept | Description |
|---|---|
| **Space** | Named container with owner + member roster at `spaces/{spaceId}/_access`. |
| **Node** | Entry in a space's object tree with `access` (`"public"` \| `"space"` \| `"invite"`) and `enc` (bool). |
| **SpaceLayout** | Protocol that produces all storage paths and cap scopes. Inject a custom layout or use `default_space_layout()`. |
| **Session** | Central runtime object: identity keys + Starfish clients + resolved layout. |
| **Space keyring** | One AES-256-GCM keyring per space encrypts all `enc` nodes. |
| **Inbox** | Monthly-sharded public-write ring buffer for sealed resource requests. |

## Quick start

```python
from starfish_spaces import build_session, make_space_client, default_space_layout

session = await build_session(
    passphrase="…",
    server_url="https://sync.example.com",
    layout=default_space_layout(),
)

client = make_space_client(session)

# Create a space
space_id = await client.registry.create_space(name="My Space")

# Invite a member
await client.members.invite(space_id, user_id=recipient_id, write=True)
```

## API surface

- **`build_session` / `derive_session`** — construct the runtime session from passphrase or device keys
- **`make_space_client`** — unified client covering registry, members, nodes, objects, inbox, identity links
- **`configure_spaces` / `default_space_layout`** — layout injection
- **`generate_seed_words` / `is_valid_seed`** — BIP-39 mnemonic helpers

See the [full guide](/extensions/spaces) for detailed documentation on all subsystems.
