"""
Starfish v3.0 — collection-owner pattern (Python mirror).

Alice owns the `shared-team` collection. She wants Bob and Carol to be
able to write encrypted documents into it.

See examples/ts/group-owner.ts for the full narrative.

Run:
    python examples/python/group_owner.py
"""

import asyncio
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from starfish_sdk import StarfishClient, SyncManager
from starfish_keyring import (
    add_collection_recipient,
    create_keyring,
    create_keyring_encryptor,
    list_recipients,
)
from starfish_identities import bootstrap_root_identity
from starfish_sharing import mint_member_cap, scopes


BASE_URL = "https://api.example.com/v1"
COLLECTION = "shared-team"


class CapProviderFromCreds:
    """Adapt a v3 DeviceCredentials into the StarfishClient CapProvider protocol."""

    def __init__(self, cap_cert: dict[str, Any], dev_ed_priv_hex: str) -> None:
        self._cap_cert = cap_cert
        self._dev_ed_priv_hex = dev_ed_priv_hex

    async def get_cap(self) -> dict[str, Any]:
        return {"cap": self._cap_cert, "dev_ed_priv_hex": self._dev_ed_priv_hex}


async def main() -> None:
    # ── 1. Bootstrap the three identities. ─────────────────────────────────
    # In a real deployment, Bob and Carol bootstrap on their own devices and
    # send Alice their KEM pubkey + user_id out-of-band (or via the pairing
    # helpers — see pairing_qr.py / pairing_relay.py).
    alice = bootstrap_root_identity("alice-passphrase")
    bob = bootstrap_root_identity("bob-passphrase")
    carol = bootstrap_root_identity("carol-passphrase")

    alice_cap_provider = CapProviderFromCreds(alice.cap_cert, alice.device["edPriv"])

    # Quiet pyflakes for unused private-key import (only used implicitly via
    # the helpers above).
    _ = Ed25519PrivateKey

    # ── 2. Alice mints `member` cap-certs for Bob and Carol. ───────────────
    bob_cap = mint_member_cap(
        alice.device["edPriv"],
        alice.device["edPub"],
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        COLLECTION,
        scopes.writer(COLLECTION),
    )
    print(f"[alice] minted member cap for bob, nonce: {bob_cap['nonce']}")

    carol_cap = mint_member_cap(
        alice.device["edPriv"],
        alice.device["edPub"],
        {"edPubHex": carol.device["edPub"], "kemPubHex": carol.device["kemPub"], "userIdHex": carol.user_id},
        COLLECTION,
        scopes.writer(COLLECTION),
    )
    print(f"[alice] minted member cap for carol, nonce: {carol_cap['nonce']}")
    # Alice ships bob_cap to Bob and carol_cap to Carol (via pairing helpers).

    # ── 3. Alice creates the keyring with all three recipients in epoch 1. ─
    keyring, _cek = create_keyring(
        adder_ed_priv_hex=alice.device["edPriv"],
        adder_ed_pub_hex=alice.device["edPub"],
        recipients=[
            alice.device["kemPub"],  # Alice herself
            bob.device["kemPub"],
            carol.device["kemPub"],
        ],
    )

    async with StarfishClient(BASE_URL, cap_provider=alice_cap_provider) as alice_client:
        keyring_sync = SyncManager(
            alice_client,
            pull_path=f"/pull/{COLLECTION}/_keyring",
            push_path=f"/push/{COLLECTION}/_keyring",
        )
        await keyring_sync.push(keyring.to_dict())

        # ── 4. Adding Dan later. ────────────────────────────────────────────
        dan = bootstrap_root_identity("dan-passphrase")
        dan_cap = mint_member_cap(
            alice.device["edPriv"],
            alice.device["edPub"],
            {"edPubHex": dan.device["edPub"], "kemPubHex": dan.device["kemPub"], "userIdHex": dan.user_id},
            COLLECTION,
            scopes.writer(COLLECTION),
        )
        _ = dan_cap

        await add_collection_recipient(
            alice_client,
            COLLECTION,
            {"subKem": dan.device["kemPub"], "userId": dan.user_id, "label": "dan"},
            {
                "edPriv": alice.device["edPriv"],
                "edPub": alice.device["edPub"],
                "kemPriv": alice.device["kemPriv"],
            },
        )
        listing = await list_recipients(alice_client, COLLECTION)
        print(f"[alice] epoch {listing['epoch']}: {len(listing['recipients'])} recipients")

    # ── 5. Bob writes an encrypted doc using his cap-cert. ─────────────────
    bob_cap_provider = CapProviderFromCreds(bob_cap, bob.device["edPriv"])
    async with StarfishClient(BASE_URL, cap_provider=bob_cap_provider) as bob_client:
        bob_keyring_sync = SyncManager(
            bob_client,
            pull_path=f"/pull/{COLLECTION}/_keyring",
            push_path=f"/push/{COLLECTION}/_keyring",
        )
        await bob_keyring_sync.pull()
        from starfish_keyring import Keyring

        bob_keyring = Keyring.from_dict(bob_keyring_sync.data)
        bob_encryptor = create_keyring_encryptor(
            bob_keyring,
            bob.device["kemPub"],
            bob.device["kemPriv"],
            trusted_adders=[alice.device["edPub"]],
        )

        bob_doc_sync = SyncManager(
            bob_client,
            pull_path=f"/pull/{COLLECTION}/doc-1",
            push_path=f"/push/{COLLECTION}/doc-1",
            encryptor=bob_encryptor,
        )
        await bob_doc_sync.push({"author": "bob", "text": "hello team"})
        print("[bob] pushed encrypted doc-1")


if __name__ == "__main__":
    asyncio.run(main())
