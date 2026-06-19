> ⚠️ **Deprecated.** The Python implementation of Starfish is no longer maintained in
> parity with the TypeScript packages and will be **removed in a future release**.
> Use the TypeScript `@drakkar.software/starfish-*` packages instead.

# starfish-sharing

Starfish member-cap extension for Python — issue scoped member capability certificates with `read_only` / `writer` / `admin` presets, and manage the per-collection `_members` directory.

## Install

```sh
pip install starfish-sdk starfish-keyring starfish-sharing
```

## Usage

```python
from starfish_sharing import mint_member_cap, scopes, add_member_entry, list_members
```

## How membership works: cryptographic & collection view

Membership has two orthogonal layers — **authorization** (a CA-signed capability cert, verified by
the server) and **key delivery** (the collection key wrapped to the member, only for
`encryption: "delegated"`). Onboarding sets both up; revoking tears both down. The server never reads
a member roster — access is decided purely from the presented cap-cert.

### Onboarding a member

**Cryptographic**

- `mint_member_cap` produces a **CA-signed bearer token**: the owner's root **Ed25519** key signs the
  canonical cert (`kind: "member"`, `iss` = owner, `sub` = member Ed25519 pubkey,
  `subKem` = member X25519 pubkey, `subUserId`, a single-collection `scope`, plus `nbf` / `exp` /
  `nonce`). The cert carries the member's **public** keys only — it holds **no secret or wrapped key
  material**.
- For `encryption: "delegated"` collections, key access is granted separately: the owner **wraps the
  collection content-encryption key (CEK) to the member's X25519 `subKem`** via the keyring's
  `add_recipient`. Mechanically: ephemeral X25519 ECDH → HKDF-SHA256 wrap key → `AES-256-GCM(cek)`,
  appended as a `WrappedKeyEntry` (itself signed by the adder) to the keyring's current epoch.
- Authorization and key delivery are **independent**: a cap with no keyring entry lets the member
  reach the collection but not decrypt it; a keyring entry with no cap lets them decrypt bytes they
  can never fetch. Onboarding a reader of a delegated collection needs **both**.
- The signed cap is delivered to the member out-of-band (or via an ordinary collection). On each
  request the member sends it in the `Authorization: Cap …` header plus a per-request Ed25519
  signature; the **server verifies the signature, time window, revocation, and scope** — it does not
  consult any roster.

**Collection (what gets written)**

| Path | Written by | Holds | Server reads it? |
|---|---|---|---|
| `<col>/_members` | `add_member_entry` (owner only) | Audit/UX roster: `{nonce, sub, subKem, subUserId, scope, nbf, exp, label?, addedBy?, addedAt}` | **No** — not an authority source |
| `<col>/_keyring` | `add_recipient` (delegated mode only) | The member's `WrappedKeyEntry` in the current epoch | **No** — stored opaquely; clients decrypt |

The cap-cert itself is **not** stored server-side as a membership record — it lives with the member.
`_members` is purely the owner's bookkeeping so they can list and later evict.

### Revoking a member

**Cryptographic**

- **Authorization kill-switch (revocation list).** The owner signs a generation-counted
  `RevocationList` (Ed25519) naming the cap by `{sub, nonce, exp}` (or `revokedSubjects` for
  incident response). The server's revocation store then rejects that cap **O(1) on every request**,
  cutting off both reads and writes immediately. This is the only thing that stops an already-issued
  cap — `exp` aside.
- **Forward secrecy (keyring rotation).** `remove_recipient` rotates the epoch: mints a **fresh CEK**,
  re-wraps it for the **retained** recipients only, and bumps `current_epoch`. The evicted member's
  X25519 key is absent from the new epoch, so they cannot decrypt content sealed afterward.
  *Caveat:* earlier epochs are preserved, so content sealed **before** rotation stays decryptable to
  anyone who already held that CEK — rotation is forward-secret, not retroactive.
- The two are independent: **revoke** stops the member acting (writes/auth); **rotate** stops them
  reading future content. Doing only one is the footgun `evict_member` exists to prevent.

**Collection (what changes)**

- `<col>/_keyring` — rotation appends a new epoch whose `wrappedKeys` omit the evicted member.
- `<col>/_members` — `remove_member_entry` drops the member's entry by `nonce`.

**Ordering matters:** revoke **first** (so a still-valid cap can't squeeze a write in between the
rotate and the revoke), then rotate the keyring, then drop the directory entry. `evict_member`
composes all three behind explicit `rotate` / `revoke` flags — see below.

## Eviction

Removing a member from the keyring (`remove_recipient`) rotates the epoch for forward
secrecy but does **not** stop them writing — write authority is cap-based. Full eviction
is revoke-the-cap **and** rotate-the-keyring **and** drop the directory entry.
`evict_member` does all three in one call behind explicit `rotate` / `revoke` flags,
removing the footgun. It is transport- and ledger-agnostic — you supply how to submit the
signed `RevocationList` and the strictly-increasing per-issuer `generation`:

```python
from starfish_sharing import evict_member

await evict_member(
    client,
    keyring_collection="shared-notes",      # <coll> → <coll>/_keyring
    members_collection="shared-notes",      # <coll> → <coll>/_members
    member={"sub": bob_ed_pub, "nonce": cap_nonce, "exp": cap_exp, "subKem": bob_kem_pub},
    adder={"edPriv": owner_ed_priv, "edPub": owner_ed_pub, "kemPriv": owner_kem_priv},
    trusted_adders=[owner_ed_pub],
    iss_ed_pub_hex=owner_ed_pub,
    iss_ed_priv_hex=owner_ed_priv,
    generation=next_generation,             # you track this (the store needs it to increase)
    submit_revocation=submit,               # async (list) -> None
    prior_revoked=prior,                    # previously-revoked entries to carry forward
    rotate=True,
    revoke=True,
)
```

The signed list is built with `build_revocation_list` from `starfish-protocol`.

## Plaintext, cap-only sharing (no keyring)

The membership flow above is the **E2E-encrypted** option (`encryption: "delegated"`):
content is sealed under a per-collection keyring and members get a wrapped CEK. For data
that does **not** need E2E encryption there is a second option: a
**plaintext** (`encryption: "none"`) shared collection where access is authorized purely
by **signed member caps + expiry**, exactly like the device mechanism. There is **no
keyring and no wrapped keys**; the server enforces read/write from the presented cap. The
two options coexist and are selected by the collection's `encryption` field.

Why it's safe to hand caps around: a cap is **subject-bound**, not a bearer token — the
server verifies every request's signature against the cap's `sub`, so a cap is usable only
by the holder of that subject's private key.

Two delivery variants:

- **Stateless (out-of-band).** Mint the cap and deliver it out-of-band; nothing is
  stored server-side (no `_keyring`, no `_members`). The owner keeps its own record of
  `{sub, nonce, exp}` to revoke later.

  ```python
  cert = mint_member_cap(
      owner_ed_priv, owner_ed_pub,
      {"edPubHex": bob_ed_pub, "kemPubHex": bob_kem_pub, "userIdHex": bob_user_id},
      "shared-board",
      scopes.writer("shared-board"),
  )
  # → hand `cert` to Bob; he presents it as `Authorization: Cap …`.
  ```

- **Owner-published caps.** Instead of forwarding, publish each signed cap into the
  single `<col>/_members` list; members fetch their own. Configure that collection
  read-open + owner-only write.

  ```python
  from starfish_sharing import publish_member_cap, fetch_my_member_cap, unpublish_member_cap

  # Owner publishes Bob's cap into the shared list:
  await publish_member_cap(client, "shared-board", cert, label="Bob")

  # Bob fetches his own cap (no forwarding) and uses it for content:
  my_cap = await fetch_my_member_cap(client, "shared-board", bob_ed_pub)
  ```

- **Public link (`audience` cap).** For a public share — a broadcast feed, a status page,
  an "anyone in this list can post" board — use `create_public_link`. It mints an
  **`audience` cap-cert** (which binds *no* single subject) and packs it into a URL
  `#fragment`. Every redeemer signs requests with **their own** identity key (sent as the
  `X-Starfish-Pub` header), so the link carries **no private key** and writes are
  attributable per user. An optional `allowed_identities` list restricts who may redeem
  (server-enforced); omit it and **any** identity may. Optional `expires_at` / `ttl_sec`
  set expiry.

  ```python
  from starfish_sharing import create_public_link, parse_public_link, redeem_public_link, scopes

  link = create_public_link(
      owner_ed_priv, owner_ed_pub,
      "broadcast", scopes.read_only("broadcast"),
      allowed_identities=[bob_ed_pub, carol_ed_pub],  # optional; omit ⇒ any identity
      ttl_sec=7 * 24 * 3600,                            # optional; or expires_at=<unix seconds>
  )
  # Share f"https://app.example/#{link.fragment}".

  # A redeemer (who already holds a Starfish identity) parses + signs as themselves:
  parsed = parse_public_link(fragment)
  headers = redeem_public_link(
      parsed,
      redeemer_ed_priv_hex=bob_ed_priv,
      redeemer_ed_pub_hex=bob_ed_pub,
      method="GET", path_and_query="/pull/broadcast/post-1", host="api.example.com",
  )
  # Send `headers` (Authorization: Cap …, X-Starfish-{Sig,Ts,Nonce,Pub}) with the request.
  ```

  The server (with `sharing_server_plugin` wired) verifies the signature against
  `X-Starfish-Pub`, checks it against the cap's `aud` when present (403 otherwise), and
  binds `auth.identity` to that redeemer's own userId. Revocation is **whole-link**: revoke
  the cap's nonce with `sub=""`, or re-mint with a trimmed `allowed_identities`. The
  `_members` directory and `evict_member` are for single-subject member caps only.

**Revocation is CRL-only** — there is nothing encrypted to rotate. Call `evict_member`
with `rotate=False` and omit the keyring params; it revokes the cap and drops the
published entry:

```python
await evict_member(
    client,
    members_collection="shared-board",
    member={"sub": bob_ed_pub, "nonce": cap_nonce, "exp": cap_exp, "subKem": bob_kem_pub},
    iss_ed_pub_hex=owner_ed_pub,
    iss_ed_priv_hex=owner_ed_priv,
    generation=next_generation,
    submit_revocation=submit,
    rotate=False,
    revoke=True,
)
```

## Server plugin

```python
from starfish_server import create_cap_cert_role_resolver
from starfish_sharing import sharing_server_plugin

resolver = create_cap_cert_role_resolver(
    nonce_cache=nonce_cache,
    revocation_store=revocation_store,
    plugins=[sharing_server_plugin],
)
```

## Role enrichers

Two generic `RoleEnricher` factories for apps that key a collection by a free id
(`products/{id}/…`, `pubspaces/{ownerId}/…`). Both take the `store`/`auth` as
arguments and depend on `starfish-server` for **types only** (under
`TYPE_CHECKING`; no runtime coupling).

### `make_registry_role_enricher` — registry / TOFU owner-member

Reads an owner-written `_registry` doc (`{owner, members}`) and grants
`owner_role` / `member_role`. With `allow_tofu=True` (default) the first writer to
a new id is granted ownership; pass `allow_tofu=False` for the strict SSE/events
variant. Fails CLOSED on store errors and on owner-less/unparseable docs.

```python
from starfish_sharing import make_registry_role_enricher

enricher = make_registry_role_enricher(
    store,
    id_param="productId",
    registry_path="products/{id}/_registry",  # {id} is substituted
    owner_role="product:owner",
    member_role="product:member",
    # allow_tofu=False,                          # strict, for /events
    # id_pattern=DEFAULT_SAFE_ID,                # ^[a-zA-Z0-9_-]+$, fullmatch
)
```

### `make_issuer_bound_role_enricher` — issuer-bound public share

Decides roles purely from the requester's cap (no store read). Grants the owner's
own device cap `owner_role` + `reader_role`; grants `reader_role` to caps the
owner delegated for one of `collections`; additionally grants `writer_role` when
such a cap carries `cap:write:<col>` and the request does not target the guard
doc.

```python
from starfish_sharing import make_issuer_bound_role_enricher

enricher = make_issuer_bound_role_enricher(
    owner_param="ownerId",
    owner_role="pubspace:owner",
    reader_role="pubspace:reader",
    writer_role="pubspace:writer",
    collections=["pubspace", "pubstream"],
    guard_param="docId",
    guard_value="_rooms",  # withholds writer_role on the registry doc
)
```

See `docs/python/sharing/` (and the TypeScript counterpart in `docs/ts/sharing/`) for the full guide.
