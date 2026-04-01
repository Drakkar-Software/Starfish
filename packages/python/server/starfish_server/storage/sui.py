"""SUI on-chain object store using dynamic fields.

This adapter stores Starfish documents as dynamic fields on a shared SUI object.
Reads are **free** (JSON-RPC queries cost no gas). Writes require a signed
transaction and consume a small amount of gas (~0.003-0.005 SUI per operation).

Fee summary
-----------
- **Store creation**: one-time ~0.01 SUI
- **Reads** (``get_string``, ``get_bytes``, ``list_keys``): FREE
- **Writes** (``put``, ``put_bytes``): ~0.003-0.005 SUI gas
- **Deletes**: ~0.002 SUI gas (storage rebate partially offsets cost)

Prerequisites
-------------
A Move smart contract must be deployed on SUI providing a shared ``Store``
object with dynamic fields.  Minimal contract interface::

    module starfish::store {
        use sui::dynamic_field;
        use std::string::String;

        public struct Store has key {
            id: UID,
        }

        public struct Entry has store, drop {
            data: vector<u8>,
            content_type: String,
        }

        /// Create a new shared Store (called once during deployment).
        public fun create(ctx: &mut TxContext) {
            transfer::share_object(Store { id: object::new(ctx) });
        }

        /// Upsert: add or overwrite a key.
        public entry fun put(
            store: &mut Store,
            key: String,
            data: vector<u8>,
            content_type: String,
        ) {
            if (dynamic_field::exists_(&store.id, key)) {
                let entry = dynamic_field::borrow_mut<String, Entry>(&mut store.id, key);
                entry.data = data;
                entry.content_type = content_type;
            } else {
                dynamic_field::add(&mut store.id, key, Entry { data, content_type });
            };
        }

        /// Remove a key.  No-op if the key does not exist.
        public entry fun remove(store: &mut Store, key: String) {
            if (dynamic_field::exists_(&store.id, key)) {
                dynamic_field::remove<String, Entry>(&mut store.id, key);
            };
        }
    }

Install the optional dependency with::

    pip install starfish-server[sui]
"""

import asyncio
import base64
from dataclasses import dataclass, field
from typing import Any

from starfish_server.storage.base import AbstractObjectStore

# Maximum size for a single SUI dynamic field value (~256 KB).
_MAX_OBJECT_BYTES = 256 * 1024

# JSON-RPC request id counter (module-level, not critical to be sequential).
_next_rpc_id = 0


def _rpc_id() -> int:
    global _next_rpc_id
    _next_rpc_id += 1
    return _next_rpc_id


@dataclass
class SuiStorageOptions:
    """Configuration for the SUI on-chain object store."""

    rpc_url: str
    """SUI JSON-RPC endpoint, e.g. ``"https://fullnode.mainnet.sui.io:443"``."""

    package_id: str
    """Object ID of the deployed Starfish storage Move package."""

    store_object_id: str
    """Object ID of the shared ``Store`` object holding dynamic fields."""

    keypair_b64: str | None = None
    """Base64-encoded Ed25519 secret key (32 bytes) for signing write
    transactions.  If ``None``, the store operates in **read-only** mode and
    all write methods will raise ``RuntimeError``."""

    network: str = "mainnet"
    """SUI network name: ``"mainnet"``, ``"testnet"``, or ``"devnet"``."""

    gas_budget: int = 10_000_000
    """Gas budget in MIST for write transactions (default 0.01 SUI)."""

    write_retry_attempts: int = 3
    """Number of retry attempts for write operations on transient failures
    (e.g. object version conflicts from concurrent access)."""

    write_retry_base_delay: float = 0.5
    """Base delay in seconds between write retries (exponential backoff)."""


class SuiObjectStore(AbstractObjectStore):
    """SUI on-chain object store backed by dynamic fields.

    Reads are performed via SUI JSON-RPC (free, no gas).  Writes require
    the ``pysui`` package and a configured keypair.

    Example::

        store = SuiObjectStore(SuiStorageOptions(
            rpc_url="https://fullnode.mainnet.sui.io:443",
            package_id="0xabc...",
            store_object_id="0xdef...",
            keypair_b64="base64-encoded-32-byte-secret-key",
        ))
    """

    def __init__(self, opts: SuiStorageOptions) -> None:
        self._opts = opts
        self._http: Any = None
        self._init_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def _get_http(self) -> Any:
        """Return a lazily-initialised ``httpx.AsyncClient``."""
        async with self._init_lock:
            if self._http is None:
                import httpx

                self._http = httpx.AsyncClient(timeout=30.0)
        return self._http

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    # ------------------------------------------------------------------
    # Helpers – JSON-RPC
    # ------------------------------------------------------------------

    async def _rpc(self, method: str, params: list[Any]) -> Any:
        """Execute a SUI JSON-RPC call and return the ``result`` field."""
        http = await self._get_http()
        payload = {
            "jsonrpc": "2.0",
            "id": _rpc_id(),
            "method": method,
            "params": params,
        }
        resp = await http.post(self._opts.rpc_url, json=payload)
        resp.raise_for_status()
        body = resp.json()
        if "error" in body:
            err = body["error"]
            raise RuntimeError(f"SUI RPC error ({method}): {err}")
        return body.get("result")

    # ------------------------------------------------------------------
    # Helpers – write transactions via pysui
    # ------------------------------------------------------------------

    def _require_signer(self) -> None:
        if self._opts.keypair_b64 is None:
            raise RuntimeError(
                "SuiObjectStore is in read-only mode (no keypair configured). "
                "Provide keypair_b64 in SuiStorageOptions to enable writes."
            )

    async def _execute_tx(self, build_fn: Any) -> Any:
        """Build, sign, and execute a transaction with retry logic.

        ``build_fn`` is an async callable that receives ``(client, signer)``
        and returns a built transaction ready for execution.
        """
        self._require_signer()

        try:
            from pysui import SuiConfig, AsyncClient
            from pysui.sui.sui_txn import SuiTransaction
        except ImportError:
            raise ImportError(
                "pysui is required for SUI write operations. "
                "Install it with: pip install starfish-server[sui]"
            )

        config = SuiConfig.user_config(
            rpc_url=self._opts.rpc_url,
            prv_keys=[self._opts.keypair_b64],
        )
        client = AsyncClient(config)

        last_exc: Exception | None = None
        for attempt in range(self._opts.write_retry_attempts):
            try:
                txn = SuiTransaction(client=client)
                await build_fn(txn)
                result = await txn.execute(gas_budget=str(self._opts.gas_budget))
                return result
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if attempt < self._opts.write_retry_attempts - 1:
                    delay = self._opts.write_retry_base_delay * (2 ** attempt)
                    await asyncio.sleep(delay)

        raise RuntimeError(
            f"SUI write failed after {self._opts.write_retry_attempts} attempts"
        ) from last_exc

    # ------------------------------------------------------------------
    # Read operations (FREE – JSON-RPC only)
    # ------------------------------------------------------------------

    async def _get_dynamic_field(self, key: str) -> dict[str, Any] | None:
        """Fetch a single dynamic field by key, returning the parsed content
        or ``None`` if the field does not exist."""
        try:
            result = await self._rpc(
                "suix_getDynamicFieldObject",
                [
                    self._opts.store_object_id,
                    {
                        "type": "0x1::string::String",
                        "value": key,
                    },
                ],
            )
        except RuntimeError:
            return None

        if result is None:
            return None

        # Check for error in the response (field not found)
        if result.get("error") is not None:
            return None

        # Navigate: result -> data -> content -> fields -> value -> fields
        try:
            content = result["data"]["content"]
            if content["dataType"] == "moveObject":
                fields = content["fields"]["value"]["fields"]
                return fields
        except (KeyError, TypeError):
            return None

        return None

    async def get_string(self, key: str) -> str | None:
        fields = await self._get_dynamic_field(key)
        if fields is None:
            return None
        # The ``data`` field is a ``vector<u8>`` represented as a base64 string
        # or a list of integers depending on the RPC serialisation.
        raw = fields.get("data")
        if raw is None:
            return None
        if isinstance(raw, str):
            return base64.b64decode(raw).decode("utf-8")
        if isinstance(raw, list):
            return bytes(raw).decode("utf-8")
        return None

    async def get_bytes(self, key: str) -> tuple[bytes, str] | None:
        fields = await self._get_dynamic_field(key)
        if fields is None:
            return None
        raw = fields.get("data")
        content_type = fields.get("content_type", "application/octet-stream")
        if raw is None:
            return None
        if isinstance(raw, str):
            return base64.b64decode(raw), content_type
        if isinstance(raw, list):
            return bytes(raw), content_type
        return None

    async def list_keys(
        self,
        prefix: str,
        *,
        start_after: str | None = None,
        limit: int | None = None,
    ) -> list[str]:
        """List dynamic field keys matching *prefix*.

        SUI's ``suix_getDynamicFields`` does not support server-side prefix
        filtering, so all field names are fetched and filtered client-side.
        This is acceptable for moderate key counts; for very large stores a
        dedicated on-chain index would be needed.
        """
        keys: list[str] = []
        cursor: str | None = None
        page_limit = 50  # SUI default / max per page

        while True:
            params: list[Any] = [self._opts.store_object_id, cursor, page_limit]
            result = await self._rpc("suix_getDynamicFields", params)
            if result is None:
                break

            for item in result.get("data", []):
                name = item.get("name", {}).get("value")
                if name is None:
                    continue
                if not name.startswith(prefix):
                    continue
                if start_after and name <= start_after:
                    continue
                keys.append(name)
                if limit and len(keys) >= limit:
                    return sorted(keys)

            if not result.get("hasNextPage", False):
                break
            cursor = result.get("nextCursor")

        return sorted(keys)

    # ------------------------------------------------------------------
    # Write operations (require pysui + keypair)
    # ------------------------------------------------------------------

    async def put(
        self,
        key: str,
        body: str,
        *,
        content_type: str | None = None,
        cache_control: str | None = None,  # noqa: ARG002 — interface parameter
    ) -> None:
        encoded = body.encode("utf-8")
        if len(encoded) > _MAX_OBJECT_BYTES:
            raise ValueError(
                f"Document size ({len(encoded)} bytes) exceeds the SUI dynamic "
                f"field limit of {_MAX_OBJECT_BYTES} bytes."
            )

        ct = content_type or "application/json"

        async def _build(txn: Any) -> None:
            txn.move_call(
                target=f"{self._opts.package_id}::store::put",
                arguments=[
                    txn.object(self._opts.store_object_id),
                    txn.pure(key),
                    txn.pure(list(encoded)),
                    txn.pure(ct),
                ],
            )

        await self._execute_tx(_build)

    async def put_bytes(
        self,
        key: str,
        body: bytes,
        *,
        content_type: str,
        cache_control: str | None = None,  # noqa: ARG002 — interface parameter
    ) -> None:
        if len(body) > _MAX_OBJECT_BYTES:
            raise ValueError(
                f"Payload size ({len(body)} bytes) exceeds the SUI dynamic "
                f"field limit of {_MAX_OBJECT_BYTES} bytes."
            )

        async def _build(txn: Any) -> None:
            txn.move_call(
                target=f"{self._opts.package_id}::store::put",
                arguments=[
                    txn.object(self._opts.store_object_id),
                    txn.pure(key),
                    txn.pure(list(body)),
                    txn.pure(content_type),
                ],
            )

        await self._execute_tx(_build)

    async def delete(self, key: str) -> None:
        async def _build(txn: Any) -> None:
            txn.move_call(
                target=f"{self._opts.package_id}::store::remove",
                arguments=[
                    txn.object(self._opts.store_object_id),
                    txn.pure(key),
                ],
            )

        await self._execute_tx(_build)

    async def delete_many(self, keys: list[str]) -> None:
        if not keys:
            return

        async def _build(txn: Any) -> None:
            for key in keys:
                txn.move_call(
                    target=f"{self._opts.package_id}::store::remove",
                    arguments=[
                        txn.object(self._opts.store_object_id),
                        txn.pure(key),
                    ],
                )

        await self._execute_tx(_build)
