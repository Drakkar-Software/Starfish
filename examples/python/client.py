"""
Starfish Python client examples.

Install:
    pip install starfish-sdk
"""

import asyncio
from starfish_sdk import StarfishClient, SyncManager, ConflictError


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


if __name__ == "__main__":
    asyncio.run(sync_manager_example())
