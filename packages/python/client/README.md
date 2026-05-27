# starfish-sdk

Python async client SDK for [Starfish](../../../README.md). Pull/push documents with hash-based conflict detection, end-to-end multi-recipient encryption, and cap-cert authorization.

## Install

```bash
pip install starfish-sdk
```

## What's in v3.0

Starfish 3.0 is a clean break from 2.x. The v2 `derive_credentials` / `generate_passphrase` / Bearer-token `auth` callback / `sign_data` / `signature_verifier` / `create_encryptor` / `group-crypto` surface is **deleted**. See [docs/migration/v2-to-v3.md](../../../docs/migration/v2-to-v3.md).

The v3 model in one sentence: a passphrase derives an Ed25519+X25519 **root identity**, which signs **capability certificates** for each device or member, and each authenticated request is itself Ed25519-signed under the cap's subject key.

## Quickstart (v3)

```python
import asyncio
from starfish_sdk import (
    StarfishClient,
    SyncManager,
    bootstrap_root_identity,
    create_keyring_encryptor,
)

async def main() -> None:
    # 1. Derive root identity + self-signed cap-cert from a passphrase.
    creds = bootstrap_root_identity(passphrase)
    # creds = DeviceCredentials(root_ed_pub, user_id, device={ed_priv,ed_pub,kem_priv,kem_pub}, cap_cert)

    # 2. Wire StarfishClient to a CapProvider — every request is signed.
    class MyCapProvider:
        async def get_cap(self):
            return {"cap": creds.cap_cert, "dev_ed_priv_hex": creds.device["ed_priv"]}

    async with StarfishClient(
        "https://api.example.com/v1",
        cap_provider=MyCapProvider(),
    ) as client:
        # 3. (Delegated only) build an encryptor from the collection's keyring.
        keyring = (await client.pull("/pull/notes/_keyring")).data
        encryptor = create_keyring_encryptor(
            keyring,
            creds.device["kem_pub"],
            creds.device["kem_priv"],
            trusted_adders=[creds.root_ed_pub],   # required — pubkey(s) you trust to grant access
        )

        # 4. Sync with optional per-push author signature.
        class MySigner:
            async def get_signer(self):
                return {
                    "dev_ed_pub_hex": creds.device["ed_pub"],
                    "sign": lambda b: ed25519_sign(creds.device["ed_priv"], b),
                }

        sync = SyncManager(
            client,
            f"/pull/notes/{creds.user_id}",
            f"/push/notes/{creds.user_id}",
            encryptor=encryptor,
            signer=MySigner(),
        )

        await sync.push({"items": ["note 1"]})  # sealed, signed, hash-checked
        await sync.pull()                        # decrypted plaintext

asyncio.run(main())
```

## Identity & key derivation

```python
from starfish_sdk import bootstrap_root_identity, derive_root_identity
```

- `derive_root_identity(passphrase)` → `RootIdentity(user_id, keys=RootKeyPair(ed_priv, ed_pub, kem_priv, kem_pub))`. Pure derivation, no cap-cert.
- `bootstrap_root_identity(passphrase)` → `DeviceCredentials(root_ed_pub, user_id, device, cap_cert)`. Use this on the first device.

`user_id = sha256(root_ed_pub)[0:32]`. Two independent HKDF derivations (signing vs KEM) give full domain separation.

Details: [docs/ts/client/11-identity-key-derivation.md](../../../docs/ts/client/11-identity-key-derivation.md).

## Cap-cert minting

```python
from starfish_sdk import mint_device_cap, mint_member_cap, scopes, MintOpts, ScopePreset
```

- `mint_device_cap(root_ed_priv, root_ed_pub, subject, scope, opts=None)` — subject acts as a proxy for the issuer (`auth.identity = issUserId`). Use for additional devices the user controls.
- `mint_member_cap(root_ed_priv, root_ed_pub, subject, scope, opts=None)` — subject keeps its own identity (`auth.identity = subUserId`); cap adds collection-scoped roles only.

### Scope presets

| Preset | Ops | Paths |
|---|---|---|
| `scopes.read_only(c)` | `read`, `list` | `c/*` |
| `scopes.writer(c)` | `read`, `list`, `write` | `c/*`, `!c/_keyring` (cannot grant new recipients) |
| `scopes.admin(c)` | `read`, `list`, `write` | `c/*` (can grant via the keyring) |
| `scopes.root_all()` | all | `*` (device caps only) |

The `!` prefix in `paths` is a denylist; explicit deny beats wildcard allow.

Details: [docs/ts/client/25-capability-certs.md](../../../docs/ts/client/25-capability-certs.md).

## Pairing additional devices

Three onboarding flows, all returning the same `DeviceCredentials` shape:

| Flow | Network | Helpers |
|---|---|---|
| Bootstrap (first device) | none | `bootstrap_root_identity(passphrase)` |
| QR (in-person, server-free) | none | `build_pairing_qr` → `parse_pairing_qr` → `assemble_pairing_bundle` → `install_pairing_bundle` |
| Server-relay (remote, 6-digit code) | 2 TTL'd Starfish documents | `build_pairing_request` → `read_pairing_request` → `build_pairing_response` → `read_pairing_response` → `install_pairing_bundle` |

```python
from starfish_sdk import (
    bootstrap_root_identity,
    build_pairing_qr,
    parse_pairing_qr,
    assemble_pairing_bundle,
    install_pairing_bundle,
    build_pairing_request,
    read_pairing_request,
    build_pairing_response,
    read_pairing_response,
    derive_code_key,
)
```

`derive_code_key(code, salt, iterations=600_000)` is the PBKDF2-HMAC-SHA256 used by the relay flow. The relayed request also carries an Ed25519 proof-of-possession signature over the device keys; `read_pairing_request` rejects a request whose `popSig` does not verify.

Full walkthroughs: [docs/ts/client/24-pairing.md](../../../docs/ts/client/24-pairing.md).

## Multi-recipient delegated encryption

A `"delegated"` collection has data documents (opaque ciphertext) plus one **keyring document** at `<collection>/_keyring` that wraps the current Content Encryption Key (CEK) for each recipient via X25519 ECDH + HKDF + AES-256-GCM (HPKE-DHKEM style).

### Low-level keyring API

```python
from starfish_sdk import (
    create_keyring,
    add_recipient,            # low-level: append entry to an in-memory keyring
    rotate_epoch,
    wrap_for_recipient,
    unwrap_from_entry,
    verify_entry_signature,
    create_keyring_encryptor,
    Keyring,
    KeyringEpoch,
    WrappedKeyEntry,
    KeyringEncryptor,
    KEYRING_WRAP_SALT,
    KEYRING_WRAP_INFO,
    KEYRING_IV_BYTES,
)
```

- `create_keyring(adder, recipients, cek=None, added_at=None)` — first-time setup, generates a CEK if not provided.
- `add_recipient(keyring, adder, current_cek, recipient_kem_hex, added_at=None)` — appends one wrap entry to the current epoch.
- `rotate_epoch(keyring, adder, retained_recipients, added_at=None)` — mints a fresh CEK in `currentEpoch + 1`, re-wraps for the retained set.
- `create_keyring_encryptor(keyring, kem_pub_hex, kem_priv_hex, trusted_adders=[...], *, min_epoch=None)` — returns an `Encryptor` compatible with `SyncManager`. Encrypts under `currentEpoch`; decrypts any epoch the device has a wrap for. The recipient keys are two positional hex strings; `trusted_adders` is **required** (raises without it); keyword-only `min_epoch` rejects a rolled-back keyring below the last-seen epoch.

### Collection-scoped recipient management

```python
from starfish_sdk import (
    add_collection_recipient,   # adds + pushes the keyring back to the server
    remove_recipient,
    list_recipients,
    current_epoch,
    keyring_path_for,
    RecipientRef,
    AdderKeys,
    ListedRecipient,
)
```

These wrap the low-level helpers with HTTP I/O via `StarfishClient`: each operation pulls the keyring, mutates it, and pushes back with hash-checked optimistic concurrency. `add_collection_recipient`, `remove_recipient`, and `list_recipients` all **require** a keyword-only `trusted_adders` pin (they raise without one); `list_recipients` returns only provenance-verified entries.

Details + algorithm + threat model: [docs/ts/client/23-multi-recipient-delegated.md](../../../docs/ts/client/23-multi-recipient-delegated.md).

## `StarfishClient`

```python
StarfishClient(
    base_url,
    cap_provider=...,    # v3 — signs every request. Replaces v2 auth callback.
    fetch=...,           # optional custom httpx client / transport
)
```

`CapProvider` is a protocol with a single async method:

```python
class CapProvider(Protocol):
    async def get_cap(self) -> dict[str, Any]:
        """Return {"cap": <CapCert dict>, "dev_ed_priv_hex": <str>}."""
```

When a `cap_provider` is set, every outgoing request carries `Authorization: Cap <base64(stable_stringify(cap))>` plus `X-Starfish-Sig`, `X-Starfish-Ts`, `X-Starfish-Nonce`.

Omit `cap_provider` for unauthenticated public reads.

## `SyncManager`

```python
SyncManager(
    client, pull_path, push_path,
    encryptor=...,           # typically create_keyring_encryptor(...)
    signer=...,              # SyncSigner — replaces v2 sign_data
    on_conflict=..., max_retries=3, validate=..., logger=...,
)
```

- `signer.get_signer()` returns `{"dev_ed_pub_hex": ..., "sign": async fn}`. When set, every push attaches `authorPubkey = cap.sub` and `authorSignature = base64(Ed25519(payload))` over the encrypted payload (without the author fields).
- `encryptor` is the only encryption option — the v2 single-secret `encryption_secret`/`encryption_salt` shorthand was removed in v3.

## `AppendLogCursor`

Incremental, stateful cursor over an append-only collection — the log counterpart to `SyncManager`. It owns the accumulated array and pulls only what's new; the checkpoint is **derived from the last element it holds**, so it resumes from persisted data on a fresh page.

```python
log = AppendLogCursor(
    client, "/pull/events",
    append_field="items",        # default
    initial_items=...,           # warm-start seed (raw {ts,data} envelopes) — or since=...
    encryptor=...,               # optional: decrypt each element's data (ts/author preserved)
    verify_author=...,           # optional: True | {"expected_author_pubkey": ..., "alg": ...}
    on_element_error="throw",    # optional: "throw" (default) | "skip" — see below
    persist_encrypted=False,     # optional: keep ciphertext for E2EE-safe persistence — see below
)
fresh = await log.pull()         # only elements newer than the last held (safe to call concurrently)
log.items                        # full accumulated log (ciphertext under persist_encrypted)
log.get_decrypted_items()        # full log decrypted — render warm-started history
log.checkpoint                   # max ts held — persist, and restore via set_checkpoint()
```

- Cold start (no seed) → first `pull()` fetches the whole collection; warm start (seeded) → resumes incrementally.
- `verify_author` verifies each element's author signature over the stored (pre-decryption) data and raises `AppendAuthorError` atomically on any failure (nothing is appended, checkpoint unchanged).
- `on_element_error="skip"` drops an element that fails verify/decrypt **and advances the checkpoint past it** (never re-fetched), so one unreadable element in a multi-writer / E2EE log can't blank the whole log. Default `"throw"` keeps the atomic behavior. SECURITY: `"skip"` also drops author-verification failures silently — combine with `verify_author`'s `expected_author_pubkey` or a post-pull `authorPubkey` check for strict authorship.
- `persist_encrypted=True` (with an `encryptor`) stores each element's **ciphertext** so `log.items` is safe to persist at rest for an E2EE log; `pull()` still returns decrypted, and `get_decrypted_items()` decrypts the full held log for warm-start rendering.
- `pull()` is safe to call concurrently — overlapping calls serialize internally (via an `asyncio.Lock`) so they never double-append a window.

## Removed in v3.0

`derive_credentials`, `generate_passphrase`, `build_invite_url`, `parse_invite_url` (the v2 passphrase identity surface), `create_encryptor` and the `SyncManager` `encryption_secret`/`encryption_salt`/`encryption_info` options, `wrap_group_key`, `create_group_keyring`, `add_group_member`, `rotate_group_key`, `create_group_encryptor`, the v2 `auth` Bearer callback, the `sign_data` callback, and the `signature_verifier` server hook are all gone. Code that imports any of them will fail to import against v3.

Migration runbook: [docs/migration/v2-to-v3.md](../../../docs/migration/v2-to-v3.md).

## Development

```bash
uv sync
uv run pytest -v
```
