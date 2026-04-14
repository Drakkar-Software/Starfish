"""
Single-collection group encryption example.

Shows the minimal setup for sharing one encrypted Starfish collection
among a small group of users:

  1. Admin creates a keyring and includes themselves as a member.
  2. Each member builds their own encryptor from the keyring.
  3. Members push / pull through SyncManager — the server only ever
     sees {"_encrypted": "...", "_epoch": N}; plaintext never leaves the client.

No batching, chunking, or separate keyring collection is required.
The keyring is distributed out-of-band (e.g. stored in each member's
private vault or shared via a secure channel).

Install:
    pip install starfish-sdk
"""

import asyncio

from starfish_sdk import StarfishClient, SyncManager
from starfish_sdk.group import (
    GroupKeyring,
    GroupKeyPair,
    derive_group_key_pair,
    create_group_keyring,
    add_group_member,
    rotate_group_key,
    create_group_encryptor,
)

BASE_URL = "https://api.example.com/v1"
COLLECTION_PATH = "/groups/g1/notes"


# ---------------------------------------------------------------------------
# Step 1 — Admin: create the keyring (run once, store result securely)
#
# The admin includes their own public key so they can also encrypt/decrypt.
# ---------------------------------------------------------------------------

async def admin_setup() -> tuple[GroupKeyring, str]:
    admin_kp = derive_group_key_pair("admin-passphrase", "admin")
    alice_kp = derive_group_key_pair("alice-passphrase", "alice")
    bob_kp   = derive_group_key_pair("bob-passphrase",   "bob")

    # Admin is included in members so they can encrypt/decrypt too
    keyring, gek = create_group_keyring(
        admin_kp,
        {
            "admin": admin_kp.public_key,
            "alice": alice_kp.public_key,
            "bob":   bob_kp.public_key,
        },
    )

    # Distribute `keyring` to all members (e.g. push to each member's vault).
    # Store `gek` in the admin's private vault — needed to add future members.
    print(f"keyring created, epoch: {keyring.current_epoch}")
    return keyring, gek


# ---------------------------------------------------------------------------
# Step 2 — Member: build encryptor from keyring and use SyncManager
# ---------------------------------------------------------------------------

async def member_push(
    user_id: str,
    passphrase: str,
    keyring: GroupKeyring,
    data: dict,
) -> None:
    my_kp = derive_group_key_pair(passphrase, user_id)
    encryptor = create_group_encryptor(keyring, user_id, my_kp.private_key)

    async def auth(*, method: str, path: str, body: str | None) -> dict[str, str]:
        return {"Authorization": f"Bearer token-{user_id}"}

    async with StarfishClient(BASE_URL, auth=auth) as client:
        sync = SyncManager(
            client,
            pull_path=f"/pull{COLLECTION_PATH}",
            push_path=f"/push{COLLECTION_PATH}",
            encryptor=encryptor,  # replaces encryption_secret / encryption_salt
        )
        await sync.push(data)

    print(f"[{user_id}] pushed encrypted data")


async def member_pull(
    user_id: str,
    passphrase: str,
    keyring: GroupKeyring,
) -> dict:
    my_kp = derive_group_key_pair(passphrase, user_id)
    encryptor = create_group_encryptor(keyring, user_id, my_kp.private_key)

    async def auth(*, method: str, path: str, body: str | None) -> dict[str, str]:
        return {"Authorization": f"Bearer token-{user_id}"}

    async with StarfishClient(BASE_URL, auth=auth) as client:
        sync = SyncManager(
            client,
            pull_path=f"/pull{COLLECTION_PATH}",
            push_path=f"/push{COLLECTION_PATH}",
            encryptor=encryptor,
        )
        result = await sync.pull()

    print(f"[{user_id}] pulled and decrypted:", result.data)
    return result.data


# ---------------------------------------------------------------------------
# Step 3 — Admin: add a new member without rotating the key
# ---------------------------------------------------------------------------

async def add_member(
    keyring: GroupKeyring,
    gek: str,
    new_member_id: str,
    new_member_passphrase: str,
) -> GroupKeyring:
    admin_kp = derive_group_key_pair("admin-passphrase", "admin")
    new_member_kp = derive_group_key_pair(new_member_passphrase, new_member_id)

    updated = add_group_member(keyring, admin_kp, gek, new_member_id, new_member_kp.public_key)
    print(f"added {new_member_id} to epoch {updated.current_epoch}")
    # Distribute `updated` to all members
    return updated


# ---------------------------------------------------------------------------
# Step 4 — Admin: remove a member by rotating to a new epoch
#
# The removed member keeps their old-epoch key but cannot decrypt new documents.
# ---------------------------------------------------------------------------

async def remove_member(
    keyring: GroupKeyring,
    remaining_members: dict[str, str],  # user_id → public_key
) -> tuple[GroupKeyring, str]:
    admin_kp = derive_group_key_pair("admin-passphrase", "admin")

    rotated, new_gek = rotate_group_key(keyring, admin_kp, remaining_members)
    print(f"rotated to epoch {rotated.current_epoch}")
    # Distribute `rotated` to remaining members; store `new_gek` in admin's vault
    return rotated, new_gek


# ---------------------------------------------------------------------------
# Demonstration (illustrative — requires a real server to run)
# ---------------------------------------------------------------------------

async def main() -> None:
    keyring, gek = await admin_setup()

    # Members push and pull
    await member_push("alice", "alice-passphrase", keyring, {"entries": ["note 1"]})
    await member_pull("bob", "bob-passphrase", keyring)

    # Admin can also push/pull (included as a member above)
    await member_pull("admin", "admin-passphrase", keyring)

    # Add a new member
    updated_keyring = await add_member(keyring, gek, "charlie", "charlie-passphrase")

    # Remove bob — collect remaining member public keys first
    admin_kp   = derive_group_key_pair("admin-passphrase",   "admin")
    alice_kp   = derive_group_key_pair("alice-passphrase",   "alice")
    charlie_kp = derive_group_key_pair("charlie-passphrase", "charlie")
    await remove_member(
        updated_keyring,
        {
            "admin":   admin_kp.public_key,
            "alice":   alice_kp.public_key,
            "charlie": charlie_kp.public_key,
        },
    )


if __name__ == "__main__":
    asyncio.run(main())
