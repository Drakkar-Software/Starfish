# starfish-sdk

Python client SDK for the [Starfish](../../README.md) document sync protocol.

## Installation

```bash
pip install starfish-sdk
```

## Usage

```python
import asyncio
from starfish_sdk import StarfishClient, SyncManager

async def main():
    async with StarfishClient("https://your-server.com/v1") as client:
        sync = SyncManager(client, "/pull/users/me/settings", "/push/users/me/settings")

        # Pull remote data
        result = await sync.pull()
        print(result.data)

        # Push local changes (auto-retries on conflict)
        await sync.push({"theme": "dark", "lang": "en"})

asyncio.run(main())
```

### With authentication

```python
async def auth(method: str, path: str, body: str | None) -> dict[str, str]:
    return {"Authorization": "Bearer <token>"}

client = StarfishClient("https://your-server.com/v1", auth=auth)
```

### With client-side encryption

```python
sync = SyncManager(
    client,
    "/pull/users/me/settings",
    "/push/users/me/settings",
    encryption_secret="my-secret",
    encryption_salt="user-identity",
)
```

## Development

```bash
uv pip install -e ".[dev]"
pytest
```
