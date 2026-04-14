"""
Starfish Python client examples.

Install:
    pip install starfish-sdk
"""

import asyncio
from datetime import date
from starfish_sdk import StarfishClient, SyncManager, ConflictError
from starfish_sdk.group import (
    GroupKeyring,
    derive_group_key_pair,
    create_group_keyring,
    add_group_member,
    rotate_group_key,
    create_group_encryptor,
)


BASE_URL = "https://api.example.com/v1"
USER_ID = "user-abc"


async def auth(*, method: str, path: str, body: str | None) -> dict[str, str]:
    """Return auth headers for each request."""
    return {"Authorization": f"Bearer my-token-{USER_ID}"}


# ---------------------------------------------------------------------------
# Low-level: pull / push directly
# ---------------------------------------------------------------------------

async def low_level_example():
    async with StarfishClient(BASE_URL, auth=auth) as client:
        # Pull current state
        result = await client.pull(f"/pull/users/{USER_ID}/settings")
        print("current data:", result.data)
        print("hash:", result.hash)

        # Push an update (base_hash must match current hash)
        new_data = {**result.data, "theme": "dark"}
        success = await client.push(
            f"/push/users/{USER_ID}/settings",
            new_data,
            base_hash=result.hash,
        )
        print("pushed, new hash:", success.hash)


# ---------------------------------------------------------------------------
# High-level: SyncManager with automatic conflict resolution
# ---------------------------------------------------------------------------

async def sync_manager_example():
    async with StarfishClient(BASE_URL, auth=auth) as client:
        sync = SyncManager(
            client,
            pull_path=f"/pull/users/{USER_ID}/settings",
            push_path=f"/push/users/{USER_ID}/settings",
        )

        await sync.pull()
        print("data after pull:", sync.data)

        await sync.push({"theme": "dark", "lang": "en"})
        print("push done, hash:", sync.hash)


# ---------------------------------------------------------------------------
# E2E encryption (client-side, server never sees plaintext)
# ---------------------------------------------------------------------------

async def encrypted_example():
    async with StarfishClient(BASE_URL, auth=auth) as client:
        sync = SyncManager(
            client,
            pull_path=f"/pull/users/{USER_ID}/notes",
            push_path=f"/push/users/{USER_ID}/notes",
            encryption_secret="user-generated-secret",
            encryption_salt=USER_ID,
        )

        await sync.pull()
        # data is automatically decrypted after pull
        print("decrypted data:", sync.data)

        # data is automatically encrypted before push
        await sync.push({"items": ["note 1", "note 2"]})


# ---------------------------------------------------------------------------
# Custom conflict resolver
# ---------------------------------------------------------------------------

async def conflict_example():
    def merge_lists(local: dict, remote: dict) -> dict:
        """Merge list fields; remote wins for scalars."""
        merged = {**remote}
        for key, local_val in local.items():
            if isinstance(local_val, list) and isinstance(remote.get(key), list):
                # union of both lists
                merged[key] = list({*local_val, *remote[key]})
        return merged

    async with StarfishClient(BASE_URL, auth=auth) as client:
        sync = SyncManager(
            client,
            pull_path=f"/pull/users/{USER_ID}/notes",
            push_path=f"/push/users/{USER_ID}/notes",
            on_conflict=merge_lists,
            max_retries=5,
        )

        try:
            await sync.push({"items": ["new note"]})
        except ConflictError:
            print("conflict could not be resolved after max retries")


# ---------------------------------------------------------------------------
# Group encryption — admin creates a group keyring
#
# Each member derives an X25519 key pair deterministically from their
# passphrase. The admin wraps the Group Encryption Key (GEK) for each
# member and pushes the keyring document to Starfish.
# ---------------------------------------------------------------------------

async def group_admin_setup() -> tuple[GroupKeyring, str]:
    admin_kp = derive_group_key_pair("admin-passphrase", "admin")
    alice_kp = derive_group_key_pair("alice-passphrase", "alice")
    bob_kp   = derive_group_key_pair("bob-passphrase",   "bob")

    keyring, gek = create_group_keyring(
        admin_kp,
        {"alice": alice_kp.public_key, "bob": bob_kp.public_key},
    )

    async def admin_auth(*, method: str, path: str, body: str | None) -> dict[str, str]:
        return {"Authorization": "Bearer my-token-admin"}

    # Push keyring in plaintext — the wrapped keys inside are ciphertext
    async with StarfishClient(BASE_URL, auth=admin_auth) as client:
        keyring_sync = SyncManager(
            client,
            pull_path="/pull/groups/g1/keyring",
            push_path="/push/groups/g1/keyring",
        )
        await keyring_sync.push(keyring.to_dict())

    # Keep `gek` in the admin's private vault — needed to add future members
    print(f"group keyring created, epoch: {keyring.current_epoch}")
    return keyring, gek


# ---------------------------------------------------------------------------
# Group encryption — member posts an encrypted message
#
# The member pulls the keyring, unwraps their GEK copy, and uses the
# resulting Encryptor with SyncManager (replaces encryption_secret/salt).
# ---------------------------------------------------------------------------

async def group_member_post(user_id: str, passphrase: str, message: str) -> None:
    my_kp = derive_group_key_pair(passphrase, user_id)

    async def member_auth(*, method: str, path: str, body: str | None) -> dict[str, str]:
        return {"Authorization": f"Bearer my-token-{user_id}"}

    async with StarfishClient(BASE_URL, auth=member_auth) as client:
        # Pull keyring
        keyring_sync = SyncManager(
            client,
            pull_path="/pull/groups/g1/keyring",
            push_path="/push/groups/g1/keyring",
        )
        await keyring_sync.pull()
        keyring = GroupKeyring.from_dict(keyring_sync.data)
        encryptor = create_group_encryptor(keyring, user_id, my_kp.private_key)

        # Write to encrypted chat collection
        today = date.today().isoformat()
        chat_sync = SyncManager(
            client,
            pull_path=f"/pull/groups/g1/chat/{today}",
            push_path=f"/push/groups/g1/chat/{today}",
            encryptor=encryptor,  # replaces encryption_secret / encryption_salt
        )

        def append_message(current: dict) -> dict:
            messages = list(current.get("messages", []))
            messages.append({"author": user_id, "text": message})
            return {**current, "messages": messages}

        await chat_sync.update(append_message)

    print(f"[{user_id}] posted: \"{message}\"")


# ---------------------------------------------------------------------------
# Group encryption — admin adds a new member (no key rotation)
# ---------------------------------------------------------------------------

async def group_add_member(current_gek: str, new_member_id: str, new_member_public_key: str) -> None:
    admin_kp = derive_group_key_pair("admin-passphrase", "admin")

    async def admin_auth(*, method: str, path: str, body: str | None) -> dict[str, str]:
        return {"Authorization": "Bearer my-token-admin"}

    async with StarfishClient(BASE_URL, auth=admin_auth) as client:
        keyring_sync = SyncManager(
            client,
            pull_path="/pull/groups/g1/keyring",
            push_path="/push/groups/g1/keyring",
        )
        await keyring_sync.pull()
        keyring = GroupKeyring.from_dict(keyring_sync.data)
        updated = add_group_member(keyring, admin_kp, current_gek, new_member_id, new_member_public_key)
        await keyring_sync.push(updated.to_dict())

    print(f"added {new_member_id} to epoch {updated.current_epoch}")


# ---------------------------------------------------------------------------
# Group encryption — admin removes a member via key rotation
#
# A new epoch is created with a new GEK. The removed member retains their
# old-epoch key (can still read old documents) but has no key for new ones.
# ---------------------------------------------------------------------------

async def group_remove_member(remaining_members: dict[str, str]) -> str:
    admin_kp = derive_group_key_pair("admin-passphrase", "admin")

    async def admin_auth(*, method: str, path: str, body: str | None) -> dict[str, str]:
        return {"Authorization": "Bearer my-token-admin"}

    async with StarfishClient(BASE_URL, auth=admin_auth) as client:
        keyring_sync = SyncManager(
            client,
            pull_path="/pull/groups/g1/keyring",
            push_path="/push/groups/g1/keyring",
        )
        await keyring_sync.pull()
        keyring = GroupKeyring.from_dict(keyring_sync.data)
        rotated, new_gek = rotate_group_key(keyring, admin_kp, remaining_members)
        await keyring_sync.push(rotated.to_dict())

    print(f"rotated to epoch {rotated.current_epoch} — removed member loses access to new documents")
    return new_gek  # store securely in admin's private vault


# ---------------------------------------------------------------------------
# Group encryption — single-collection (admin as member)
#
# Simpler variant: the keyring is built in memory and distributed
# out-of-band (e.g. stored in each member's private vault). No separate
# keyring collection in Starfish is needed. The admin includes themselves
# in the members map so they can also encrypt/decrypt.
# ---------------------------------------------------------------------------

async def group_single_collection_setup() -> tuple[GroupKeyring, str]:
    admin_kp = derive_group_key_pair("admin-passphrase", "admin")
    alice_kp = derive_group_key_pair("alice-passphrase", "alice")
    bob_kp   = derive_group_key_pair("bob-passphrase",   "bob")

    # Admin includes themselves as a member so they can encrypt/decrypt too
    keyring, gek = create_group_keyring(
        admin_kp,
        {
            "admin": admin_kp.public_key,
            "alice": alice_kp.public_key,
            "bob":   bob_kp.public_key,
        },
    )

    # Distribute `keyring` to all members (e.g. push to each member's private vault)
    # Store `gek` in the admin's private vault — needed to add future members
    print(f"single-collection keyring created, epoch: {keyring.current_epoch}")
    return keyring, gek


async def group_single_collection_push(
    user_id: str,
    passphrase: str,
    keyring: GroupKeyring,
    data: dict,
) -> None:
    my_kp = derive_group_key_pair(passphrase, user_id)
    encryptor = create_group_encryptor(keyring, user_id, my_kp.private_key)

    async def auth(*, method: str, path: str, body: str | None) -> dict[str, str]:
        return {"Authorization": f"Bearer my-token-{user_id}"}

    # One encrypted collection — encryptor replaces encryption_secret / encryption_salt
    async with StarfishClient(BASE_URL, auth=auth) as client:
        sync = SyncManager(
            client,
            pull_path="/pull/groups/g1/notes",
            push_path="/push/groups/g1/notes",
            encryptor=encryptor,
        )
        await sync.push(data)

    print(f"[{user_id}] pushed encrypted data")


async def group_single_collection_pull(
    user_id: str,
    passphrase: str,
    keyring: GroupKeyring,
) -> dict:
    my_kp = derive_group_key_pair(passphrase, user_id)
    encryptor = create_group_encryptor(keyring, user_id, my_kp.private_key)

    async def auth(*, method: str, path: str, body: str | None) -> dict[str, str]:
        return {"Authorization": f"Bearer my-token-{user_id}"}

    async with StarfishClient(BASE_URL, auth=auth) as client:
        sync = SyncManager(
            client,
            pull_path="/pull/groups/g1/notes",
            push_path="/push/groups/g1/notes",
            encryptor=encryptor,
        )
        result = await sync.pull()

    print(f"[{user_id}] pulled and decrypted:", result.data)
    return result.data


if __name__ == "__main__":
    asyncio.run(sync_manager_example())
