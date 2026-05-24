"""
Starfish v3.0 — server-relay pairing demo (Python mirror).

See examples/ts/pairing-relay.ts for the full sequence narrative.
Plaintext request:   {devEdPub, devKemPub}
Plaintext response:  PairingBundle as JSON
Both are encrypted with AES-GCM keyed off
PBKDF2(code, salt = b"starfish-pair" + request_nonce).

Run:
    python examples/python/pairing_relay.py
"""

import asyncio

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from starfish_identities import (
    AssemblePairingBundleOpts,
    assemble_pairing_bundle,
    bootstrap_root_identity,
    build_pairing_qr,
    build_pairing_request,
    build_pairing_response,
    install_pairing_bundle,
    parse_pairing_qr,
    read_pairing_request,
    read_pairing_response,
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
    PAIRING_CODE = "428193"  # 6-digit numeric, shown briefly on root device

    # ── Root device. ────────────────────────────────────────────────────────
    root = bootstrap_root_identity("correct-horse-battery-staple")
    _keyring, notes_cek = create_keyring(
        adder_ed_priv_hex=root.device["edPriv"],
        adder_ed_pub_hex=root.device["edPub"],
        recipients=[root.device["kemPub"]],
    )

    # ── New device. ─────────────────────────────────────────────────────────
    new_dev_ed_priv, new_dev_ed_pub = _ed25519_pair()
    new_dev_kem_priv, new_dev_kem_pub = _x25519_pair()

    # ── Step 1: new device → relay (encrypted PairingRequest). ──────────────
    # The request carries a proof-of-possession signature over the device keys
    # (made with edPriv), so a relay cannot swap the KEM pubkey it controls.
    encrypted_req = build_pairing_request(
        {"edPriv": new_dev_ed_priv, "edPub": new_dev_ed_pub, "kemPub": new_dev_kem_pub},
        PAIRING_CODE,
    )
    print(f"[new-device] uploaded request, nonce: {encrypted_req.request_nonce}")

    # Relay would now store this blob keyed by some short-lived handle and the
    # root device polls for it. We simulate the round-trip:
    relayed_request = encrypted_req

    # ── Step 2: root reads request, decides scope. ──────────────────────────
    decrypted = read_pairing_request(relayed_request, PAIRING_CODE)
    print(f"[root] received request for dev_ed_pub: {decrypted['devEdPub'][:16]}…")

    # New device declared no scope; root device decides what to grant. Here:
    # read-only on "notes". Build a parsed-QR shape so we can reuse
    # `assemble_pairing_bundle` (same shape as the QR variant).
    parsed = parse_pairing_qr(
        build_pairing_qr(decrypted["devEdPub"], decrypted["devKemPub"], scopes.read_only("notes"))
    )

    bundle = assemble_pairing_bundle(
        {"edPriv": root.device["edPriv"], "edPub": root.device["edPub"]},
        parsed,
        {"notes": {"epoch": 1, "cek": notes_cek}},
        AssemblePairingBundleOpts(granted_scope=parsed.requested_scope),
    )

    # ── Step 3: root → relay (encrypted PairingResponse). ───────────────────
    encrypted_resp = build_pairing_response(
        bundle, PAIRING_CODE, relayed_request.request_nonce
    )
    print("[root] uploaded response")

    # ── Step 4: new device polls relay, decrypts response. ──────────────────
    recovered_bundle = read_pairing_response(encrypted_resp, PAIRING_CODE)
    print("[new-device] received bundle, installing…")

    installed = install_pairing_bundle(
        recovered_bundle,
        {
            "edPriv": new_dev_ed_priv,
            "edPub": new_dev_ed_pub,
            "kemPriv": new_dev_kem_priv,
            "kemPub": new_dev_kem_pub,
        },
    )

    print(f"[new-device] paired; user_id = {installed.credentials.user_id}")
    print(f"[new-device] CEKs recovered: {list(installed.ceks.keys())}")
    # The new device now has a cap-cert scoped to read notes/* and the CEKs
    # needed to decrypt the documents under that path. The relay never saw
    # the cap-cert in plaintext.


if __name__ == "__main__":
    asyncio.run(main())
