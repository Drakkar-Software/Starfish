"""
Starfish v3.0 Python client examples.

Demonstrates the v3 surface:
    • passphrase → root identity (Ed25519 + X25519)
    • signed cap-cert minted locally (server holds no keys)
    • StarfishClient + cap-cert request signing
    • SyncManager + delegated multi-recipient encryption via keyring

Install:
    pip install starfish-sdk

Run:
    python examples/python/client.py
"""

import asyncio
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from starfish_sdk import (
    StarfishClient,
    SyncManager,
    ConflictError,
)
from starfish_keyring import (
    create_keyring,
    create_keyring_encryptor,
    add_collection_recipient,
    list_recipients,
)
from starfish_identities import bootstrap_root_identity
from starfish_sharing import mint_member_cap, scopes
from starfish_entitlements import pull_entitlements


BASE_URL = "https://api.example.com/v1"


# ---------------------------------------------------------------------------
# Cap-cert provider — adapts a DeviceCredentials into the CapProvider
# protocol StarfishClient expects.
# ---------------------------------------------------------------------------


class CapProviderFromCreds:
    """Adapts a v3 DeviceCredentials into a StarfishClient cap-provider."""

    def __init__(self, cap_cert: dict[str, Any], dev_ed_priv_hex: str) -> None:
        self._cap_cert = cap_cert
        self._dev_ed_priv_hex = dev_ed_priv_hex

    async def get_cap(self) -> dict[str, Any]:
        return {"cap": self._cap_cert, "dev_ed_priv_hex": self._dev_ed_priv_hex}


class SignerFromKeys:
    """Adapts a device Ed25519 keypair into a SyncSigner."""

    def __init__(self, dev_ed_pub_hex: str, dev_ed_priv_hex: str) -> None:
        self._dev_ed_pub_hex = dev_ed_pub_hex
        self._priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(dev_ed_priv_hex))

    async def get_signer(self) -> dict[str, Any]:
        async def sign(payload: bytes) -> bytes:
            return self._priv.sign(payload)

        return {"dev_ed_pub_hex": self._dev_ed_pub_hex, "sign": sign}


# ---------------------------------------------------------------------------
# First user, first device: bootstrap a v3 root identity from a passphrase.
# ---------------------------------------------------------------------------


async def bootstrap_first_device() -> None:
    creds = bootstrap_root_identity("correct-horse-battery-staple")
    print("user_id:", creds.user_id)
    print("root_ed_pub:", creds.root_ed_pub)

    cap_provider = CapProviderFromCreds(creds.cap_cert, creds.device["edPriv"])
    signer = SignerFromKeys(creds.device["edPub"], creds.device["edPriv"])

    async with StarfishClient(BASE_URL, cap_provider=cap_provider) as client:
        sync = SyncManager(
            client,
            pull_path=f"/pull/users/{creds.user_id}/settings",
            push_path=f"/push/users/{creds.user_id}/settings",
            signer=signer,
        )

        await sync.pull()
        await sync.push({"theme": "dark", "lang": "en"})
        print("settings pushed, hash:", sync.hash)


# ---------------------------------------------------------------------------
# Delegated multi-recipient encryption.
#
# v3 stores per-collection keyrings at <collection>/_keyring; each recipient
# gets the CEK wrapped for their X25519 pubkey.
# ---------------------------------------------------------------------------


async def delegated_encrypted_collection() -> None:
    creds = bootstrap_root_identity("correct-horse-battery-staple")

    # Build a brand-new keyring with epoch 1 wrapping a fresh random CEK
    # for our own device.
    keyring, _cek = create_keyring(
        adder_ed_priv_hex=creds.device["edPriv"],
        adder_ed_pub_hex=creds.device["edPub"],
        recipients=[creds.device["kemPub"]],
    )

    cap_provider = CapProviderFromCreds(creds.cap_cert, creds.device["edPriv"])
    signer = SignerFromKeys(creds.device["edPub"], creds.device["edPriv"])

    async with StarfishClient(BASE_URL, cap_provider=cap_provider) as client:
        # Push the keyring (plaintext document; wrapped CEKs inside are
        # ciphertext).
        keyring_sync = SyncManager(
            client,
            pull_path="/pull/notes/_keyring",
            push_path="/push/notes/_keyring",
            signer=signer,
        )
        await keyring_sync.push(keyring.to_dict())

        # Build an encryptor for our device and write an encrypted document.
        encryptor = create_keyring_encryptor(
            keyring,
            creds.device["kemPub"],
            creds.device["kemPriv"],
            trusted_adders=[creds.device["edPub"]],
        )

        notes_sync = SyncManager(
            client,
            pull_path=f"/pull/users/{creds.user_id}/notes",
            push_path=f"/push/users/{creds.user_id}/notes",
            encryptor=encryptor,
            signer=signer,
        )
        await notes_sync.push({"items": ["first encrypted note"]})
        print("encrypted notes pushed; epoch:", keyring.current_epoch)


# ---------------------------------------------------------------------------
# Adding a teammate to a shared keyring.
#
# Alice mints a `member` cap-cert for Bob with writer scope on shared-team,
# then adds Bob to the keyring so he can decrypt shared-team payloads.
# ---------------------------------------------------------------------------


async def share_with_teammate(bob_ed_pub_hex: str, bob_kem_pub_hex: str, bob_user_id_hex: str) -> None:
    alice = bootstrap_root_identity("alice-passphrase")
    alice_cap_provider = CapProviderFromCreds(alice.cap_cert, alice.device["edPriv"])

    # 1. Mint a member cap-cert for Bob.
    bob_member_cap = mint_member_cap(
        alice.device["edPriv"],
        alice.device["edPub"],
        {"edPubHex": bob_ed_pub_hex, "kemPubHex": bob_kem_pub_hex, "userIdHex": bob_user_id_hex},
        "shared-team",
        scopes.writer("shared-team"),
    )
    print("minted member cap-cert for Bob:", bob_member_cap["nonce"])
    # Bob installs this cap-cert into his device storage (out-of-band,
    # e.g. QR or relay).

    # 2. Add Bob to the keyring.
    async with StarfishClient(BASE_URL, cap_provider=alice_cap_provider) as client:
        await add_collection_recipient(
            client,
            "shared-team",
            {"subKem": bob_kem_pub_hex, "userId": bob_user_id_hex, "label": "bob"},
            {
                "edPriv": alice.device["edPriv"],
                "edPub": alice.device["edPub"],
                "kemPriv": alice.device["kemPriv"],
            },
        )
        listing = await list_recipients(client, "shared-team")
        print(f"shared-team epoch {listing['epoch']}: {len(listing['recipients'])} recipient(s)")


# ---------------------------------------------------------------------------
# Conflict resolution + retries.
# ---------------------------------------------------------------------------


async def conflict_example(creds: Any) -> None:
    def merge_lists(local: dict, remote: dict) -> dict:
        merged = {**remote}
        for key, local_val in local.items():
            if isinstance(local_val, list) and isinstance(remote.get(key), list):
                merged[key] = list({*local_val, *remote[key]})
        return merged

    cap_provider = CapProviderFromCreds(creds.cap_cert, creds.device["edPriv"])
    async with StarfishClient(BASE_URL, cap_provider=cap_provider) as client:
        sync = SyncManager(
            client,
            pull_path=f"/pull/users/{creds.user_id}/notes",
            push_path=f"/push/users/{creds.user_id}/notes",
            on_conflict=merge_lists,
            max_retries=5,
        )
        try:
            await sync.push({"items": ["new note"]})
        except ConflictError:
            print("conflict could not be resolved after max retries")


# ---------------------------------------------------------------------------
# Binary blobs (avatars, attachments).
# ---------------------------------------------------------------------------


async def binary_example(creds: Any) -> None:
    cap_provider = CapProviderFromCreds(creds.cap_cert, creds.device["edPriv"])
    async with StarfishClient(BASE_URL, cap_provider=cap_provider) as client:
        png_bytes = bytes([0x89, 0x50, 0x4E, 0x47])
        push_result = await client.push_blob(
            f"/push/users/{creds.user_id}/avatar",
            png_bytes,
            "image/png",
        )
        print("avatar hash:", push_result.hash)

        blob = await client.pull_blob(f"/pull/users/{creds.user_id}/avatar")
        print("content type:", blob.content_type)
        print("etag hash:", blob.hash)
        print("size (bytes):", len(blob.data))


# ---------------------------------------------------------------------------
# Entitlements.
# ---------------------------------------------------------------------------


async def entitlements_example(creds: Any) -> None:
    cap_provider = CapProviderFromCreds(creds.cap_cert, creds.device["edPriv"])
    async with StarfishClient(BASE_URL, cap_provider=cap_provider) as client:
        features = await pull_entitlements(client, creds.user_id)
        print("my entitlements:", features)
        if "premium-package-1" in features:
            r = await client.pull("/pull/premium/latest-report")
            print("premium content:", r.data)


# ---------------------------------------------------------------------------
# Public-read (no cap-cert needed).
# ---------------------------------------------------------------------------


async def public_read_example() -> None:
    # Omit cap_provider for collections whose read_roles include "public".
    async with StarfishClient(BASE_URL) as client:
        r = await client.pull("/pull/posts/welcome")
        print("public post:", r.data)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


async def main() -> None:
    await bootstrap_first_device()
    # await delegated_encrypted_collection()
    # await share_with_teammate(...)
    # ... etc.


if __name__ == "__main__":
    asyncio.run(main())
