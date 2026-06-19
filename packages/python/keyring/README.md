> ⚠️ **Deprecated.** The Python implementation of Starfish is no longer maintained in
> parity with the TypeScript packages and will be **removed in a future release**.
> Use the TypeScript `@drakkar.software/starfish-*` packages instead.

# starfish-keyring

Starfish multi-recipient encryption layer for Python — keyring documents, recipient management, AES-GCM payload encryption.

This is the encryption extension for Starfish v3. It is independent of `starfish-sdk` transport in the sense that the core `StarfishClient` does not import it; apps that want client-side payload encryption install this package and wire it on top.

## Install

```sh
pip install starfish-sdk starfish-keyring
```

## Usage

```python
from starfish_sdk import StarfishClient
from starfish_keyring import (
    create_keyring,
    create_keyring_encryptor,
    add_collection_recipient,
)

keyring, cek = create_keyring(adder_ed_priv, adder_ed_pub, [alice_kem_pub])
encryptor = create_keyring_encryptor(
    keyring,
    alice_kem_pub,
    alice_kem_priv,
    trusted_adders=[adder_ed_pub],   # required — Ed25519 pubkey(s) you trust to grant access
)
```

`trusted_adders` is **required** (raises without it): the per-entry `addedSig` is self-attesting, so a provenance pin is needed to reject a server-substituted wrap entry. Pass the keyword-only `min_epoch` (the highest `current_epoch` you've previously seen, persisted client-side) to reject a stale keyring a hostile server might serve to undo a rotation. The recipient-management helpers (`add_collection_recipient`, `remove_recipient`, `list_recipients`) require the same `trusted_adders` pin.

The encryptor exposes `encrypt`/`decrypt` for JSON payloads and `seal_bytes(data, aad=None)` / `open_bytes(blob, aad=None)` for raw binary attachments (stored via the client's `push_blob` in an `encryption: "none"` binary collection). A sealed blob is `[u32 BE epoch][12-byte IV][AES-256-GCM ciphertext‖tag]`; the epoch and the caller's `aad` (typically the blob's storage path) are bound into the GCM tag, so a hostile server cannot relocate the blob to another path or replay it at a different epoch. This is byte-compatible with the TypeScript keyring's `sealBytes`/`openBytes`, so a blob sealed in one language opens in the other.

## Epochs & rotation

Revoking a recipient (`remove_recipient`) **rotates** the keyring to a new epoch and re-wraps the CEK for everyone who remains, so the revoked party can't read new content. `add_collection_recipient` wraps a newcomer into the **current epoch only** — content sealed under an earlier epoch stays unreadable to them (you'll see `No key available for epoch N` on decrypt). To share existing content with a freshly-added recipient, **re-seal it at the current epoch** (decrypt with a key that holds the old CEK, then re-encrypt) after adding them.

See `docs/python/keyring/` (and the TypeScript counterpart in `docs/ts/keyring/`) for the full guide.
