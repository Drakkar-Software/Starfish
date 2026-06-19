> ⚠️ **Deprecated.** The Python implementation of Starfish is no longer maintained in
> parity with the TypeScript packages and will be **removed in a future release**.
> Use the TypeScript `@drakkar.software/starfish-*` packages instead.

# starfish-identities

Starfish root + device identity extension for Python — passphrase-derived root identities, device cap-cert minting, multi-device pairing flows, and the per-user device directory.

## Install

```sh
pip install starfish-sdk starfish-keyring starfish-identities
```

## Usage

```python
from starfish_identities import bootstrap_root_identity, mint_device_cap, scopes, add_device_entry, list_devices

me = bootstrap_root_identity("correct horse battery staple")
```

## Root identity derivation

`bootstrap_root_identity` / `derive_root_identity` derive the root keypairs
deterministically from the passphrase, so the same human re-derives them on any
device with no stored secret:

- **Argon2id** (memory-hard) stretches the passphrase into a 32-byte master —
  `m=47104 KiB ≈ 46 MiB, t=3, p=1`, global salt `"starfish-v3-root"` (derivation
  must be reproducible from the passphrase alone, so the salt cannot be per-user).
  Locked as `ARGON2_PARAMS`.
- **HKDF-SHA256** expands the master into two domain-separated seeds: an Ed25519
  signing key (`info="ed25519"`) and an X25519 KEM key (`info="x25519"`) — used for
  exactly one of {sign, key-agreement} each, never both.
- `user_id = sha256(root_ed_pub)[0:32]`.

Byte-identical to the TypeScript derivation; locked by
[`tests/test-vectors/identity-derivation.json`](../../../tests/test-vectors/identity-derivation.json).

## One-way device provisioning (configurable caps + expiry)

The QR / server-relay flows are *two-way*: the new device generates its own
keypair and sends a request back. `provision_device` is the *one-way* alternative
— the root device plays both roles, producing a single hand-off blob — and it is
where you choose **what the new device may do** (`scope`) and **how long its cap
lives** (`ttl_sec`). The same knobs exist on the two-way flow via
`AssemblePairingBundleOpts(granted_scope=..., ttl_sec=...)`.

```python
import json
from starfish_identities import (
    provision_device,
    install_provisioned_device,
    ProvisionDeviceOpts,
    ProvisionedDevice,
    scopes,
)

# Root device: generate the new device, mint its cap with a chosen scope + exp.
provisioned = provision_device(
    {"edPriv": me.device["edPriv"], "edPub": me.device["edPub"]},
    ProvisionDeviceOpts(
        scope=scopes.root_all(),       # REQUIRED — or a narrower scope to bound the device
        ttl_sec=7 * 24 * 3600,         # optional, default 30 days
        # current_epoch_by_collection={"notes": {"epoch": e, "cek": cek}},  # optional
    ),
)
setup_code = json.dumps(provisioned.to_dict())  # hand off out-of-band

# New device: install the blob (uses the keys carried inside it).
installed = install_provisioned_device(ProvisionedDevice.from_dict(json.loads(setup_code)))
```

- **`scope` is required** — provisioning never silently grants root. Pass
  `scopes.root_all()` for a full account clone, or a narrower scope to bound the
  device. The server enforces it: a cap whose `ops` omit `write` synthesizes no
  write role, so writes return 403.
- **`current_epoch_by_collection`** wraps existing CEKs into the bundle so the new
  device can read existing ciphertext (it lives inside the opts here, whereas
  `assemble_pairing_bundle` takes it as a positional argument).
- **Security:** the new device's **private keys are generated off-device** and
  travel inside the result. Whoever reads the blob owns a full clone of the
  device. Use one-way provisioning only over a channel you would trust with the
  collection keys themselves; prefer the two-way QR / relay flow otherwise.

## QR-in / auto-return pairing (anonymous rendezvous)

For a device that **can't scan** (e.g. a laptop), keep the camera on the *root*
device: the new device shows its QR, the root scans it and pushes the assembled
bundle to a small **anonymous, TTL'd rendezvous slot**, and the new device fetches
it with a single trigger — no manual bundle-back, no polling. The new device is
credential-less (no cap-cert yet), so it reaches the public slot with an anonymous
client; this is safe because the bundle's CEKs are E2E-wrapped to the new device's
KEM and the channel needs only delivery.

```python
from starfish_identities import (
    build_pairing_qr, parse_pairing_qr, assemble_pairing_bundle, install_pairing_bundle,
    push_pairing_bundle, fetch_pairing_bundle, clear_pairing_bundle, generate_device_keys,
    AssemblePairingBundleOpts, scopes,
)

# New device: show a QR (carries qr_nonce); anon_client has no cap_provider.
dev = generate_device_keys()
qr = build_pairing_qr(dev["edPub"], dev["kemPub"], requested_scope, qr_nonce=qr_nonce_bytes)

# Root device: parse, assemble, and push to the rendezvous slot.
parsed = parse_pairing_qr(qr)
bundle = assemble_pairing_bundle(
    root_ed_key, parsed, {},  # third arg is per-collection CEKs, if any
    opts=AssemblePairingBundleOpts(granted_scope=scopes.root_all()),  # REQUIRED
)
await push_pairing_bundle(anon_client, parsed.qr_nonce, bundle)

# New device, on a single "Added from root" click — None means "not there yet".
bundle2 = await fetch_pairing_bundle(anon_client, qr_nonce)
if bundle2 is not None:
    installed = install_pairing_bundle(
        bundle2, dev,
        expected_qr_nonce=qr_nonce,
        expected_root_ed_pub=known_root_pub,  # pin: rejects a bundle from a different root
    )
    await clear_pairing_bundle(anon_client, qr_nonce)  # best-effort one-shot
```

- **`granted_scope` is required.** The QR-supplied `requested_scope` is
  attacker-influenceable, so callers **must** pass an explicit `granted_scope` to
  bound the delegated authority — `assemble_pairing_bundle` fails closed (raises
  `ValueError`) without it rather than defaulting to the requested scope.
- **`expected_root_ed_pub`** pins the issuer so an attacker's own root can't answer
  an open rendezvous and provision the device into *their* account. When the new
  device doesn't know the root pubkey, show its fingerprint for the user to verify.
- The slot is keyed by `rendezvous_path_for(qr_nonce)` = `_pairing/<hex(qr_nonce)>`
  — no new QR field; `qr_nonce` was never secret. The app/server provides the
  collection: `encryption="none"`, `public` read/write, a short `ttl_ms`, a tight
  body cap; one-shot is the new device overwriting the slot after install.

## Same identity on every device (the simplest multi-device model)

Pairing/provisioning give each device its own key pair (so you can revoke one device), but a
per-device key is **not** a recipient in rooms owned by *other* people — its bundle CEK is a
snapshot that goes stale on the owner's next epoch rotation, and a member can't enroll its own
device in someone else's keyring. The simplest way to give every device the **same** membership is
to skip pairing and **re-enter the passphrase**: `bootstrap_root_identity` is deterministic, so each
device re-derives the identical root identity and is the *same principal and KEM recipient*. It can
then present any cap minted to your root (including member caps), unwrap any CEK wrapped to your
root KEM, and **keep reading across the owner's rotations** (every device re-derives the same key).
The trade-off: the master key lives on every device, so there is **no per-device revocation** and
losing any device compromises the account. The member-cap JSON others issued you and the room list
are app-level state that must still travel to the new device. See
[`docs/ts/client/24-pairing.md` §5](../../../docs/ts/client/24-pairing.md).

## Sealing a setup code with a passphrase

A one-way setup code (or any secret blob) can be sealed under a user-chosen
PIN/passphrase so the code alone is useless if intercepted — send the PIN over a
**different channel** than the code:

```python
from starfish_identities import seal_with_passphrase, open_with_passphrase, is_sealed_envelope

env = seal_with_passphrase(pin, setup_code_json.encode("utf-8"))  # JSON-serialisable dict
# hand over json.dumps(env); transmit the PIN separately

if is_sealed_envelope(parsed):
    data = open_with_passphrase(pin, parsed)  # one generic ValueError on any failure
```

`key = Argon2id(NFC(passphrase), random-salt)` → AES-256-GCM. `open_with_passphrase`
validates the KDF parameters **before** running Argon2id (so a hostile envelope
can't force a multi-GiB computation) and collapses every failure — wrong
passphrase, tampering, bad params — into one generic error. Strength is bounded by
passphrase entropy: a short numeric PIN is still offline-brute-forceable, so the
seal buys a revocation window, not permanent safety. Byte-identical to the
TypeScript `sealWithPassphrase`, locked by `tests/test-vectors/passphrase-seal.json`.

## Server plugin

```python
from starfish_server import create_cap_cert_role_resolver
from starfish_identities import identities_server_plugin

resolver = create_cap_cert_role_resolver(
    nonce_cache=nonce_cache,
    revocation_store=revocation_store,
    plugins=[identities_server_plugin],
)
```

See `docs/python/identities/` (and the TypeScript counterpart in `docs/ts/identities/`) for the full guide.
