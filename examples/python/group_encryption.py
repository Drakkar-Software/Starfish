"""
Starfish group encryption example (Python).

Shows the full lifecycle: group creation, member join, cross-member
read/write, adding a member, and revoking a member via key rotation.

Install:
    pip install starfish-sdk

Server config needed (encryption: "group"):
    see examples/python/server.py and add the collections below.
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
GROUP_ID = "group-abc"


# ---------------------------------------------------------------------------
# Helper: create an authenticated StarfishClient for a given identity
# ---------------------------------------------------------------------------

def make_client(user_id: str) -> StarfishClient:
    async def auth(*, method: str, path: str, body: str | None) -> dict[str, str]:
        return {"Authorization": f"Bearer my-token-{user_id}"}

    return StarfishClient(BASE_URL, auth=auth)


# ---------------------------------------------------------------------------
# Step 1 — Admin creates the group keyring
#
# The admin derives their X25519 key pair from their passphrase (deterministic,
# no key storage required), then wraps the Group Encryption Key (GEK) for each
# founding member's public key.
# ---------------------------------------------------------------------------

async def admin_create_group() -> None:
    admin_passphrase = "admin-secret-passphrase"
    admin_user_id = "admin"

    # Each member must publish their public key first.
    # Here we simulate fetching alice's and bob's public keys.
    alice_kp = derive_group_key_pair("alice-secret-passphrase", "alice")
    bob_kp = derive_group_key_pair("bob-secret-passphrase", "bob")

    admin_kp = derive_group_key_pair(admin_passphrase, admin_user_id)

    # Wrap the GEK for every founding member
    keyring, gek = create_group_keyring(
        admin_kp,
        {
            "alice": alice_kp.public_key,
            "bob": bob_kp.public_key,
        },
    )

    print(f"Created keyring, epoch: {keyring.current_epoch}")
    print(f"Members: {list(keyring.epochs['1'].wrapped_keys.keys())}")

    # Push keyring to Starfish (plaintext — the wrapped keys are already ciphertext)
    async with make_client(admin_user_id) as client:
        keyring_sync = SyncManager(
            client,
            pull_path=f"/pull/groups/{GROUP_ID}/keyring",
            push_path=f"/push/groups/{GROUP_ID}/keyring",
            # No encryptor — keyring document is stored in plaintext
        )
        await keyring_sync.push(keyring.to_dict())

    # IMPORTANT: keep `gek` to add future members. Store it in the admin's
    # encrypted private vault (encryption: "delegated"), never send to server.
    print(f"GEK (store securely): {gek[:8]}...")


# ---------------------------------------------------------------------------
# Step 2 — Member pulls keyring and writes an encrypted message
#
# Each member derives their own key pair from their passphrase, pulls the
# keyring, unwraps their GEK copy, and uses it as the Encryptor for the
# encrypted chat collection.
# ---------------------------------------------------------------------------

async def member_post_message(user_id: str, passphrase: str, message: str) -> None:
    import uuid
    import time

    my_kp = derive_group_key_pair(passphrase, user_id)

    async with make_client(user_id) as client:
        # Pull the keyring (plaintext)
        keyring_sync = SyncManager(
            client,
            pull_path=f"/pull/groups/{GROUP_ID}/keyring",
            push_path=f"/push/groups/{GROUP_ID}/keyring",
        )
        await keyring_sync.pull()
        keyring = GroupKeyring.from_dict(keyring_sync.data)

        # Create a multi-epoch encryptor from the keyring
        encryptor = create_group_encryptor(keyring, user_id, my_kp.private_key)

        # Use the encryptor with the encrypted chat collection
        from datetime import date
        today = date.today().isoformat()  # "2026-04-13"

        chat_sync = SyncManager(
            client,
            pull_path=f"/pull/groups/{GROUP_ID}/chat/{today}",
            push_path=f"/push/groups/{GROUP_ID}/chat/{today}",
            encryptor=encryptor,  # replaces encryption_secret/encryption_salt
        )

        # Append message (atomic read-modify-write with conflict retry)
        def append_message(current: dict) -> dict:
            messages = list(current.get("messages", []))
            messages.append({
                "id": str(uuid.uuid4()),
                "author": user_id,
                "text": message,
                "ts": int(time.time() * 1000),
            })
            return {**current, "messages": messages}

        await chat_sync.update(append_message)

    print(f"[{user_id}] posted: \"{message}\"")


# ---------------------------------------------------------------------------
# Step 3 — Member reads messages posted by other members
#
# All members share the same GEK for the current epoch, so any member can
# decrypt any other member's messages. The server never sees plaintext.
# ---------------------------------------------------------------------------

async def member_read_messages(user_id: str, passphrase: str) -> None:
    from datetime import date

    my_kp = derive_group_key_pair(passphrase, user_id)

    async with make_client(user_id) as client:
        # Pull keyring
        keyring_sync = SyncManager(
            client,
            pull_path=f"/pull/groups/{GROUP_ID}/keyring",
            push_path=f"/push/groups/{GROUP_ID}/keyring",
        )
        await keyring_sync.pull()
        keyring = GroupKeyring.from_dict(keyring_sync.data)
        encryptor = create_group_encryptor(keyring, user_id, my_kp.private_key)

        # Pull and decrypt today's chat
        today = date.today().isoformat()
        chat_sync = SyncManager(
            client,
            pull_path=f"/pull/groups/{GROUP_ID}/chat/{today}",
            push_path=f"/push/groups/{GROUP_ID}/chat/{today}",
            encryptor=encryptor,
        )
        await chat_sync.pull()
        messages = chat_sync.data.get("messages", [])

    print(f"[{user_id}] read {len(messages)} messages:")
    for msg in messages:
        print(f"  {msg['author']}: {msg['text']}")


# ---------------------------------------------------------------------------
# Step 4 — Admin adds a new member (no GEK rotation)
#
# The new member can read all existing epoch-1 documents and new ones.
# The admin wraps the current GEK for the new member — no re-encryption needed.
# ---------------------------------------------------------------------------

async def admin_add_member(
    admin_passphrase: str,
    admin_user_id: str,
    current_gek: str,           # kept by admin from create_group_keyring
    new_member_id: str,
    new_member_public_key: str,
) -> None:
    admin_kp = derive_group_key_pair(admin_passphrase, admin_user_id)

    async with make_client(admin_user_id) as client:
        keyring_sync = SyncManager(
            client,
            pull_path=f"/pull/groups/{GROUP_ID}/keyring",
            push_path=f"/push/groups/{GROUP_ID}/keyring",
        )
        await keyring_sync.pull()
        keyring = GroupKeyring.from_dict(keyring_sync.data)

        # Add the new member to the current epoch
        updated_keyring = add_group_member(
            keyring,
            admin_kp,
            current_gek,
            new_member_id,
            new_member_public_key,
        )

        await keyring_sync.push(updated_keyring.to_dict())

    print(f"Added {new_member_id} to epoch {updated_keyring.current_epoch}")


# ---------------------------------------------------------------------------
# Step 5 — Admin removes a member via key rotation
#
# Creates a new epoch with a new GEK. The removed member keeps their old-epoch
# key (they can still read old documents), but they have no key for epoch 2+.
# ---------------------------------------------------------------------------

async def admin_remove_member(
    admin_passphrase: str,
    admin_user_id: str,
    remaining_members: dict[str, str],  # user_id → public_key
) -> str:
    admin_kp = derive_group_key_pair(admin_passphrase, admin_user_id)

    async with make_client(admin_user_id) as client:
        keyring_sync = SyncManager(
            client,
            pull_path=f"/pull/groups/{GROUP_ID}/keyring",
            push_path=f"/push/groups/{GROUP_ID}/keyring",
        )
        await keyring_sync.pull()
        keyring = GroupKeyring.from_dict(keyring_sync.data)

        # Rotate — new epoch, new GEK, wrapped for remaining members only
        rotated_keyring, new_gek = rotate_group_key(
            keyring,
            admin_kp,
            remaining_members,
        )

        await keyring_sync.push(rotated_keyring.to_dict())

    print(
        f"Rotated to epoch {rotated_keyring.current_epoch}. "
        f"Removed member has no epoch-{rotated_keyring.current_epoch} key."
    )

    # Admin keeps the new GEK to add future members to epoch 2+
    return new_gek


# ---------------------------------------------------------------------------
# Run all examples in sequence
# ---------------------------------------------------------------------------

async def main() -> None:
    print("=== Group Encryption Example ===\n")

    print("--- Admin creates group ---")
    await admin_create_group()

    print("\n--- Alice posts a message ---")
    await member_post_message("alice", "alice-secret-passphrase", "Hello, group!")

    print("\n--- Bob reads messages ---")
    await member_read_messages("bob", "bob-secret-passphrase")

    print("\n--- Admin adds charlie ---")
    charlie_kp = derive_group_key_pair("charlie-secret-passphrase", "charlie")
    # In practice the admin fetches current_gek from their private vault
    fake_current_gek = "a" * 64  # placeholder
    await admin_add_member(
        "admin-secret-passphrase", "admin",
        fake_current_gek, "charlie", charlie_kp.public_key,
    )

    print("\n--- Admin removes bob (key rotation) ---")
    alice_kp = derive_group_key_pair("alice-secret-passphrase", "alice")
    new_gek = await admin_remove_member(
        "admin-secret-passphrase", "admin",
        {"alice": alice_kp.public_key, "charlie": charlie_kp.public_key},
    )
    print("New GEK epoch started. Bob cannot decrypt new messages.")
    print(f"New GEK (store securely): {new_gek[:8]}...")


if __name__ == "__main__":
    asyncio.run(main())
