"""
Starfish v3.0 — server-free QR pairing demo (Python mirror).

See examples/ts/pairing-qr.ts for the full narrative. Roles:

    • Root device (existing user): bootstrap_root_identity → DeviceCredentials
    • New device: generate Ed25519 + X25519 locally, share pubkeys via QR
    • Root device assembles a PairingBundle (cap-cert + wrapped CEKs)
    • New device installs the bundle

Run:
    python examples/python/pairing_qr.py
"""

import asyncio
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from starfish_identities import (
    AssemblePairingBundleOpts,
    assemble_pairing_bundle,
    bootstrap_root_identity,
    build_pairing_qr,
    install_pairing_bundle,
    parse_pairing_qr,
)
from starfish_keyring import create_keyring
from starfish_sharing import scopes


def _ed25519_pair() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes.hex(), pub_bytes.hex()


def _x25519_pair() -> tuple[str, str]:
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes.hex(), pub_bytes.hex()


async def main() -> None:
    # ── Root device: existing user. ─────────────────────────────────────────
    root = bootstrap_root_identity("correct-horse-battery-staple")
    print(f"[root] user_id: {root.user_id}")

    # The root has some encrypted collections. For the demo we have one
    # collection "notes" with its current epoch CEK in memory.
    _keyring, notes_cek = create_keyring(
        adder_ed_priv_hex=root.device["edPriv"],
        adder_ed_pub_hex=root.device["edPub"],
        recipients=[root.device["kemPub"]],
    )
    current_by_collection = {"notes": {"epoch": 1, "cek": notes_cek}}

    # ── New device: generate a fresh device-local keypair. ──────────────────
    new_dev_ed_priv, new_dev_ed_pub = _ed25519_pair()
    new_dev_kem_priv, new_dev_kem_pub = _x25519_pair()

    # ── Encode the request as a QR string. ──────────────────────────────────
    # The new device asks for read-only access to the "notes" collection.
    qr = build_pairing_qr(
        new_dev_ed_pub,
        new_dev_kem_pub,
        scopes.read_only("notes"),
    )
    print(f"[new-device] QR payload: {qr[:60]}…")

    # ── Root device scans the QR. ───────────────────────────────────────────
    parsed = parse_pairing_qr(qr)
    print(f"[root] parsed QR for dev_ed_pub: {parsed.dev_ed_pub[:16]}…")

    # ── Root device assembles the bundle: a cap-cert + wrapped CEKs. ────────
    bundle = assemble_pairing_bundle(
        {"edPriv": root.device["edPriv"], "edPub": root.device["edPub"]},
        parsed,
        current_by_collection,
        AssemblePairingBundleOpts(granted_scope=parsed.requested_scope),
    )
    print(f"[root] bundle wraps collections: {list(bundle.wrapped_ceks.keys())}")

    # Bundle travels back to the new device (out-of-band: bluetooth, file,
    # second QR, or a brief relay round-trip — see pairing_relay.py).

    # ── New device installs the bundle. ─────────────────────────────────────
    # Root pinning is MANDATORY: install_pairing_bundle raises unless it is told
    # which root to trust (otherwise an attacker could hand the device a bundle
    # signed by their OWN root and hijack the identity). This demo already knows
    # the root's Ed25519 pubkey, so we pin it via expected_root_ed_pub. In a real
    # first-contact flow where the new device has never seen this root, pass
    # confirm_unpinned_root=lambda root_ed_pub: True instead — and a real app MUST
    # show that fingerprint to the user and get explicit confirmation.
    installed = install_pairing_bundle(
        bundle,
        {
            "edPriv": new_dev_ed_priv,
            "edPub": new_dev_ed_pub,
            "kemPriv": new_dev_kem_priv,
            "kemPub": new_dev_kem_pub,
        },
        expected_root_ed_pub=root.device["edPub"],
    )
    print(f"[new-device] installed; user_id = {installed.credentials.user_id}")
    print(f"[new-device] recovered CEKs: {list(installed.ceks.keys())}")
    # The new device persists `installed.credentials` (which contains the
    # cap-cert restricted to read-only access on notes) and the recovered
    # CEKs. It can now read encrypted documents in notes/* by using the
    # cap-cert as a CapProvider and feeding the CEK to
    # create_keyring_encryptor().

    _ = secrets  # quiet pyflakes if it ever runs on this file


if __name__ == "__main__":
    asyncio.run(main())
