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

## Invite links (single-link join)

`create_space_invite_link` produces a **bearer link** — the ephemeral member credential
rides in the URL fragment (`{origin}/join#…`), so anyone holding the link can join with no
request/grant round-trip. It is the right tool for owner-initiated sharing to a trusted
recipient (not for public "request access", which is the sealed inbox flow).

```python
from starfish_sharing.cap_mint import MintOpts

# Owner: mint a link that expires in 24h.
result = await create_space_invite_link(
    session, space_id, "My Space", True, origin,
    MintOpts(ttl_sec=24 * 3600),        # or MintOpts(expires_at=<unix seconds>); omit → 30-day default
)
link, invite_user_id = result["link"], result["inviteUserId"]

# Invitee: redeem it (rejects an expired / not-yet-valid link up front).
await join_space_by_link(session, decode_space_invite_link(fragment))

# Owner: revoke this ONE link later, using the returned handle.
await revoke_space_access(session, space_id, invite_user_id, generation=…, submit_revocation=…)
```

- **Expiry** — `ttl_sec` / `expires_at` bound the cap's `exp`; the server enforces `nbf`/`exp`
  on every request, so a lapsed link genuinely stops working. Default is 30 days.
- **Per-link revocation** — each call mints a *distinct* ephemeral member, so revoking one link
  (via its `inviteUserId`) never affects other members or links.
- **Multi-use** — bearer links are inherently reusable: there is **no** client-only single-use,
  because the secret lives entirely in the fragment and the server counts no redemptions. Use a
  short `ttl_sec` and/or revoke after the intended join.

## API surface

- **`build_session` / `derive_session`** — construct the runtime session from passphrase or device keys
- **`make_space_client`** — unified client covering registry, members, nodes, objects, inbox, identity links
- **`configure_spaces` / `default_space_layout`** — layout injection
- **`generate_seed_words` / `is_valid_seed`** — BIP-39 mnemonic helpers

See the [full guide](/extensions/spaces) for detailed documentation on all subsystems.
