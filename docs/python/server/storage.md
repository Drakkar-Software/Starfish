# Storage Backends (Python)

Starfish's `AbstractObjectStore` interface abstracts over any key/value store. The library ships three built-in implementations and makes it straightforward to bring your own.

> **TypeScript equivalent:** [docs/ts/server/storage.md](../../ts/server/storage.md)

---

## FilesystemObjectStore

Stores every document as a file on disk. Suitable for single-node deployments and local development.

**Import path:** `starfish_server` (top-level)

**Extra dependency:** `aiofiles` — install with `pip install starfish-server` (included by default)

```python
from starfish_server import FilesystemObjectStore, FilesystemStorageOptions

store = FilesystemObjectStore(
    FilesystemStorageOptions(base_dir="/var/lib/starfish/data")
)
```

| Option | Type | Description |
|---|---|---|
| `base_dir` | `str` | Root directory where objects are stored. Created automatically if absent. |

Writes are atomic: data is written to a temporary file and renamed into place so a crash mid-write never corrupts stored data.

---

## S3ObjectStore

Stores documents in any S3-compatible object store (AWS S3, MinIO, Cloudflare R2, Tigris, etc.).
Suitable for horizontally-scaled or serverless deployments.

**Import path:** `starfish_server.storage.s3`

**Extra dependency:** `aiobotocore` — install with `pip install starfish-server[s3]`

```python
from starfish_server.storage.s3 import S3ObjectStore, S3StorageOptions

store = S3ObjectStore(S3StorageOptions(
    access_key_id=os.environ["S3_ACCESS_KEY_ID"],
    secret_access_key=os.environ["S3_SECRET_ACCESS_KEY"],
    endpoint="https://s3.amazonaws.com",
    bucket="my-starfish-bucket",
    region="us-east-1",
))
```

### Options

| Option | Type | Default | Description |
|---|---|---|---|
| `access_key_id` | `str` | — | AWS / S3-compatible access key ID |
| `secret_access_key` | `str` | — | AWS / S3-compatible secret access key |
| `endpoint` | `str` | — | Base URL of the S3 service |
| `bucket` | `str` | — | Bucket name |
| `region` | `str` | `"us-east-1"` | AWS region |

### Cleanup

Call `await store.close()` on shutdown to release underlying HTTP connections:

```python
@asynccontextmanager
async def lifespan(app):
    yield
    await store.close()

app = FastAPI(lifespan=lifespan)
```

Or wire it through `GracefulShutdown`:

```python
from starfish_server.lifecycle import GracefulShutdown, GracefulShutdownOptions

shutdown = GracefulShutdown(GracefulShutdownOptions(
    on_shutdown=store.close,
))
```

### MinIO example

```python
store = S3ObjectStore(S3StorageOptions(
    access_key_id="minioadmin",
    secret_access_key="minioadmin",
    endpoint="http://localhost:9000",
    bucket="starfish",
    region="us-east-1",  # MinIO ignores this but it is required
))
```

### Cloudflare R2 example

```python
store = S3ObjectStore(S3StorageOptions(
    access_key_id=os.environ["R2_ACCESS_KEY_ID"],
    secret_access_key=os.environ["R2_SECRET_ACCESS_KEY"],
    endpoint=f"https://{os.environ['CF_ACCOUNT_ID']}.r2.cloudflarestorage.com",
    bucket="starfish",
    region="auto",
))
```

---

## MemoryObjectStore

In-process store backed by a Python dict. For unit tests only — data is lost on restart.

```python
from starfish_server import MemoryObjectStore

# Shared global dict (convenient for quick scripts)
store = MemoryObjectStore()

# Isolated instance (pass {} to prevent cross-test pollution)
store = MemoryObjectStore(data={})
```

---

## Bring your own store

Subclass `AbstractObjectStore` and implement five required methods (plus two optional binary methods):

```python
from starfish_server.storage.base import AbstractObjectStore


class MyStore(AbstractObjectStore):
    async def get_string(self, key: str) -> str | None:
        ...

    async def put(self, key: str, body: str, *, content_type: str | None = None, cache_control: str | None = None) -> None:
        ...

    async def list_keys(self, prefix: str, *, start_after: str | None = None, limit: int | None = None) -> list[str]:
        ...

    async def delete(self, key: str) -> None:
        ...

    async def delete_many(self, keys: list[str]) -> None:
        ...

    # Optional — only needed for binary (non-JSON) collections
    async def get_bytes(self, key: str) -> tuple[bytes, str] | None:
        ...

    async def put_bytes(self, key: str, body: bytes, *, content_type: str, cache_control: str | None = None) -> None:
        ...
```

Alternatively, use `CustomObjectStore` for a callback-based approach without subclassing:

```python
from starfish_server.storage.memory import CustomObjectStore

store = CustomObjectStore(
    on_get=lambda key: my_backend.get(key),
    on_put=lambda key, body, **kwargs: my_backend.set(key, body),
    on_list=lambda prefix, start_after=None, limit=100: my_backend.scan(prefix),
    on_delete=lambda key: my_backend.delete(key),
)
```

---

## Request metadata via `StoreContext`

Every store method accepts a keyword-only `context: StoreContext | None = None` argument. When a request comes in through a route handler the library fills this with structured metadata about the request:

```python
@dataclass(frozen=True)
class StoreContext:
    collection: str              # collection name from config (e.g. "profile")
    params: Mapping[str, str]    # resolved path params (e.g. {"identity": "alice"})
    identity: str | None         # authenticated caller, or None for public routes
    roles: tuple[str, ...]       # resolved roles for this caller
    action: str                  # "pull" | "push" | "list" | "delete"
    namespace: str | None        # set when route lives under a namespace mount
```

### `CustomObjectStore` — receiving context in callbacks

Callbacks that accept an extra positional argument automatically receive the context. Callbacks written with the old single-argument signature continue to work unchanged — arity is sniffed once at construction time using `inspect.signature`.

```python
from starfish_server import CustomObjectStore

# Old-style — still works, ctx is never passed
store = CustomObjectStore(
    on_get=lambda key: my_backend.get(key),
)

# New-style — receives full request context
async def on_put(key: str, body: str, ctx) -> None:
    print(f"{ctx.identity} pushed to {ctx.collection}")
    await my_backend.set(key, body)

store = CustomObjectStore(on_put=on_put)
```

System-internal calls (replica sync, config loading, enrichers) pass `None` — treat a missing context as "no request context available".
