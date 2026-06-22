"""StarfishClient construction and space-keyring / profile helpers.

This module mirrors ``starfish-spaces/src/client.ts`` and provides:

- :class:`DeviceKeys` / :class:`ClientOpts` / :class:`PublicProfile` types.
- :func:`make_space_client` / :func:`make_anon_space_client` — client factories.
- Keyring lifecycle: :func:`owner_ensure_keyring`, :func:`add_keyring_recipient_core`,
  :func:`add_space_keyring_recipient`, :func:`owner_ensure_space_keyring`,
  :func:`ensure_space_keyring_recipient`.
- Encryptor builders: :func:`open_encryptor` / :func:`build_encryptor`.
- Profile helpers: :func:`read_profile`, :func:`read_profiles`, :func:`write_profile`,
  :func:`ensure_pseudo`, :func:`ensure_profile_keys`.
- Request-signing raw-fetch helper: :func:`build_auth_headers`.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any, Optional, TypedDict

from starfish_protocol.request_signing import sign_request
from starfish_keyring import (
    Keyring,
    WrappedKeyEntry,
    add_collection_recipient,
    create_keyring,
    create_keyring_encryptor,
    unwrap_from_entry,
    wrap_for_recipient,
)
from starfish_sdk.types import ConflictError, StarfishHttpError

from starfish_spaces.cas_retry import run_cas
from starfish_spaces.request_verify import sign_kem_sig
from starfish_spaces.space_access_error import SpaceAccessError

if TYPE_CHECKING:
    from starfish_sdk import StarfishClient
    from starfish_spaces.config import SpaceLayout


# ── Types ─────────────────────────────────────────────────────────────────────


class DeviceKeys(TypedDict):
    """Hex-encoded Ed25519 sign + X25519 KEM keypair for a device."""

    edPriv: str
    edPub: str
    kemPriv: str
    kemPub: str


class ClientOpts(TypedDict, total=False):
    """Connection parameters for :func:`make_space_client`."""

    baseUrl: str
    namespace: str
    timeout: float
    cache: Any


class PublicProfile(TypedDict, total=False):
    """Public user profile stored at ``user/{userId}/profile``."""

    pseudo: Optional[str]
    avatar: Optional[str]
    edPub: Optional[str]
    kemPub: Optional[str]
    kemSig: Optional[str]


# ── CapProvider implementation ────────────────────────────────────────────────


class _CapProvider:
    """A :class:`starfish_sdk.types.CapProvider` backed by a static cap dict + edPriv hex."""

    def __init__(self, cap: Any, ed_priv_hex: str) -> None:
        self._cap = cap
        self._ed_priv_hex = ed_priv_hex

    async def get_cap(self) -> dict[str, Any]:
        return {"cap": self._cap, "dev_ed_priv_hex": self._ed_priv_hex}


def cap_provider_for(cap: Any, ed_priv_hex: str) -> _CapProvider:
    """Build a :class:`CapProvider` from a static cap + Ed25519 private key."""
    return _CapProvider(cap, ed_priv_hex)


# ── Client factories ──────────────────────────────────────────────────────────


def make_space_client(
    cap: Any,
    ed_priv_hex: str,
    opts: ClientOpts,
) -> "StarfishClient":
    """Build a :class:`StarfishClient` authenticated with ``cap`` and ``ed_priv_hex``.

    Args:
        cap:         A signed cap-cert (or any CapProvider-compatible cap).
        ed_priv_hex: The device's Ed25519 private key (hex) for request signing.
        opts:        Connection parameters (``baseUrl``, ``namespace``, …).

    Returns:
        A configured :class:`StarfishClient`.
    """
    from starfish_sdk import StarfishClient

    provider = cap_provider_for(cap, ed_priv_hex)
    return StarfishClient(
        opts["baseUrl"],
        cap_provider=provider,
        namespace=opts.get("namespace"),
        timeout=float(opts.get("timeout", 30.0)),
    )


def make_anon_space_client(opts: ClientOpts) -> "StarfishClient":
    """Build an unauthenticated :class:`StarfishClient` (for public-read paths)."""
    from starfish_sdk import StarfishClient

    return StarfishClient(
        opts["baseUrl"],
        cap_provider=None,
        namespace=opts.get("namespace"),
        timeout=float(opts.get("timeout", 30.0)),
    )


# ── Auth-header builder (for raw-fetch helpers) ───────────────────────────────


def build_auth_headers(
    cap: Any,
    ed_priv_hex: str,
    method: str,
    path_and_query: str,
    body: Optional[str],
    base_url: str,
) -> dict[str, str]:
    """Build v3 auth headers for a raw-fetch operation.

    Mirrors the TS ``buildAuthHeaders`` helper used by ``readNodeWithLinkCap`` /
    ``writeNodeWithLinkCap``.
    """
    import base64

    from starfish_protocol.constants import (
        HEADER_AUTHORIZATION,
        HEADER_NONCE,
        HEADER_SIG,
        HEADER_TS,
    )
    from starfish_protocol.hash import stable_stringify

    try:
        import httpx
        host = httpx.URL(base_url).netloc
        if isinstance(host, bytes):
            host = host.decode("ascii")
    except Exception:
        host = ""

    body_bytes = body.encode("utf-8") if body else b""
    sig = sign_request(method, path_and_query, body_bytes, ed_priv_hex, host=host)
    cap_b64 = base64.b64encode(stable_stringify(cap).encode("utf-8")).decode("ascii")
    return {
        HEADER_AUTHORIZATION: f"Cap {cap_b64}",
        HEADER_SIG: sig.sig,
        HEADER_TS: str(sig.ts),
        HEADER_NONCE: sig.nonce,
    }


# ── Keyring lifecycle ─────────────────────────────────────────────────────────

_MAX_KEYRING_ATTEMPTS = 3


def _adder_keys(keys: DeviceKeys) -> dict[str, str]:
    return {"edPriv": keys["edPriv"], "edPub": keys["edPub"], "kemPriv": keys["kemPriv"]}


async def is_keyring_missing(
    client: "StarfishClient",
    keyring_pull_path: str,
) -> bool:
    """Return ``True`` when the keyring doc does not exist on the server."""
    try:
        result = await client.pull(keyring_pull_path)
        # A PullResult with empty data means the doc doesn't exist yet.
        data = getattr(result, "data", result)
        return data is None or data == {} or not data
    except StarfishHttpError as exc:
        if exc.status == 404:
            return True
        raise


async def is_already_present_recipient(
    client: "StarfishClient",
    collection_name: str,
    sub_kem: str,
) -> bool:
    """Return ``True`` when ``sub_kem`` is already listed in the keyring collection."""
    try:
        from starfish_keyring import list_recipients
        recipients = await list_recipients(client, collection_name)
        return any(r.get("subKem") == sub_kem for r in recipients)
    except Exception:
        return False


async def add_keyring_recipient_core(
    client: "StarfishClient",
    collection_name: str,
    recipient: dict[str, str],
    adder: dict[str, str],
    trusted_adders: Optional[list[str]] = None,
) -> None:
    """Add a keyring recipient, swallowing already-present errors."""
    try:
        await add_collection_recipient(
            client,
            collection_name,
            recipient,  # type: ignore[arg-type]
            adder,  # type: ignore[arg-type]
            trusted_adders=trusted_adders,
        )
    except ConflictError:
        raise  # re-raise for CAS retry in the outer loop
    except Exception as exc:
        # Swallow "already present" errors gracefully.
        msg = str(exc).lower()
        if "already" in msg or "present" in msg or "duplicate" in msg:
            return
        raise


async def owner_ensure_keyring(
    client: "StarfishClient",
    keys: DeviceKeys,
    collection_name: str,
    keyring_pull_path: str,
    keyring_push_path: str,
    trusted_adders: Optional[list[str]] = None,
) -> None:
    """Ensure the keyring for ``collection_name`` exists and that the owner is in it.

    CAS-safe: retries up to 3 times on :class:`ConflictError`.  Creates a fresh
    keyring doc if it does not exist yet.
    """
    adder = _adder_keys(keys)
    recipient = {
        "subKem": keys["kemPub"],
        "userId": None,
    }

    async def attempt() -> None:
        missing = await is_keyring_missing(client, keyring_pull_path)
        if missing:
            # Create a new keyring with the owner as sole recipient.
            keyring, _cek = create_keyring(
                adder["edPriv"],
                adder["edPub"],
                [keys["kemPub"]],
            )
            push_result = await client.pull(keyring_pull_path)
            base_hash = getattr(push_result, "hash", None)
            kr_data = keyring.to_dict() if hasattr(keyring, "to_dict") else keyring
            await client.push(keyring_push_path, kr_data, base_hash)
        else:
            await add_keyring_recipient_core(
                client,
                collection_name,
                recipient,  # type: ignore[arg-type]
                adder,
                trusted_adders=trusted_adders,
            )

    await run_cas(attempt)


async def add_space_keyring_recipient(
    client: "StarfishClient",
    keys: DeviceKeys,
    collection_name: str,
    recipient: dict[str, str],
    trusted_adders: Optional[list[str]] = None,
) -> None:
    """Add a recipient to an existing space keyring collection."""
    await add_keyring_recipient_core(
        client,
        collection_name,
        recipient,
        _adder_keys(keys),
        trusted_adders=trusted_adders,
    )


async def owner_ensure_space_keyring(
    client: "StarfishClient",
    keys: DeviceKeys,
    space_id: str,
    layout: "SpaceLayout",
    trusted_adders: Optional[list[str]] = None,
) -> None:
    """Ensure the space-wide keyring exists for ``space_id``."""
    await owner_ensure_keyring(
        client,
        keys,
        layout.keyring_name(space_id),
        layout.keyring_pull(space_id),
        layout.keyring_push(space_id),
        trusted_adders=trusted_adders,
    )


async def ensure_space_keyring_recipient(
    client: "StarfishClient",
    keys: DeviceKeys,
    space_id: str,
    recipient: dict[str, str],
    layout: "SpaceLayout",
    trusted_adders: Optional[list[str]] = None,
) -> None:
    """Ensure ``recipient`` is in the space keyring for ``space_id``."""
    await add_space_keyring_recipient(
        client,
        keys,
        layout.keyring_name(space_id),
        recipient,
        trusted_adders=trusted_adders,
    )


# ── Encryptor builders ────────────────────────────────────────────────────────


async def open_encryptor(
    client: "StarfishClient",
    collection_name: str,
    kem_priv: str,
    trusted_adders: Optional[list[str]] = None,
    space_id: Optional[str] = None,
    node_id: Optional[str] = None,
) -> Any:
    """Open an :class:`KeyringEncryptor` for ``collection_name``.

    Raises:
        SpaceAccessError: if the keyring doc is not accessible.
    """
    try:
        pull_path = f"/pull/{collection_name}/_keyring"
        result = await client.pull(pull_path)
        from starfish_keyring import Keyring
        data = result.data if hasattr(result, "data") else result
        keyring = Keyring.from_dict(data) if hasattr(Keyring, "from_dict") else data
        encryptor = create_keyring_encryptor(keyring, None, kem_priv, trusted_adders=trusted_adders)
        return encryptor
    except (StarfishHttpError, Exception) as exc:
        raise SpaceAccessError(space_id or collection_name, node_id, str(exc)) from exc


async def build_encryptor(
    client: "StarfishClient",
    collection_name: str,
    kem_priv: str,
    trusted_adders: Optional[list[str]] = None,
    space_id: Optional[str] = None,
    node_id: Optional[str] = None,
) -> Optional[Any]:
    """Like :func:`open_encryptor` but returns ``None`` instead of raising."""
    try:
        return await open_encryptor(
            client, collection_name, kem_priv, trusted_adders, space_id, node_id
        )
    except Exception:
        return None


# ── Profile helpers ───────────────────────────────────────────────────────────


async def _fetch_profile_raw(
    client: "StarfishClient",
    user_id: str,
    layout: "SpaceLayout",
) -> Optional[dict[str, Any]]:
    try:
        result = await client.pull(layout.profile_pull(user_id))
        return result.data if hasattr(result, "data") else result
    except StarfishHttpError:
        return None
    except Exception:
        return None


def _coerce_profile(raw: Optional[dict[str, Any]]) -> PublicProfile:
    if not raw or not isinstance(raw, dict):
        return {}  # type: ignore[return-value]
    return {
        "pseudo": raw.get("pseudo"),
        "avatar": raw.get("avatar"),
        "edPub": raw.get("edPub"),
        "kemPub": raw.get("kemPub"),
        "kemSig": raw.get("kemSig"),
    }  # type: ignore[return-value]


async def read_profile(
    client: "StarfishClient",
    user_id: str,
    layout: "SpaceLayout",
) -> PublicProfile:
    """Read the public profile for ``user_id`` (empty dict on missing)."""
    raw = await _fetch_profile_raw(client, user_id, layout)
    return _coerce_profile(raw)


_PROFILE_CHUNK = 24


async def read_profiles(
    client: "StarfishClient",
    user_ids: list[str],
    layout: "SpaceLayout",
) -> dict[str, PublicProfile]:
    """Batch-read profiles for ``user_ids`` (chunked at 24)."""
    result: dict[str, PublicProfile] = {}
    for i in range(0, len(user_ids), _PROFILE_CHUNK):
        chunk = user_ids[i : i + _PROFILE_CHUNK]
        # Use batch_pull_many via a single collection pull for each ID.
        for uid in chunk:
            profile = await read_profile(client, uid, layout)
            result[uid] = profile
    return result


async def write_profile(
    client: "StarfishClient",
    user_id: str,
    layout: "SpaceLayout",
    patch: dict[str, Any],
) -> None:
    """CAS-write a profile update for ``user_id``."""
    try:
        result = await client.pull(layout.profile_pull(user_id))
        current = result.data if hasattr(result, "data") else {}
        base_hash = result.hash if hasattr(result, "hash") else None
    except StarfishHttpError:
        current = {}
        base_hash = None

    merged = {**current, **patch}
    await client.push(layout.profile_push(user_id), merged, base_hash)


async def ensure_pseudo(
    client: "StarfishClient",
    user_id: str,
    layout: "SpaceLayout",
    fallback: str,
) -> str:
    """Return the user's display name, writing ``fallback`` if absent."""
    profile = await read_profile(client, user_id, layout)
    pseudo = profile.get("pseudo") if profile else None
    if pseudo:
        return pseudo
    await write_profile(client, user_id, layout, {"pseudo": fallback})
    return fallback


async def ensure_profile_keys(
    client: "StarfishClient",
    user_id: str,
    layout: "SpaceLayout",
    keys: DeviceKeys,
) -> None:
    """Write the device's public keys to the profile if not already present."""
    profile = await read_profile(client, user_id, layout)
    if (
        profile.get("edPub") == keys["edPub"]
        and profile.get("kemPub") == keys["kemPub"]
    ):
        return  # already correct — skip write
    kem_sig = sign_kem_sig(keys["kemPub"], keys["edPriv"])
    await write_profile(
        client,
        user_id,
        layout,
        {"edPub": keys["edPub"], "kemPub": keys["kemPub"], "kemSig": kem_sig},
    )


__all__ = [
    "DeviceKeys",
    "ClientOpts",
    "PublicProfile",
    "cap_provider_for",
    "make_space_client",
    "make_anon_space_client",
    "build_auth_headers",
    "is_keyring_missing",
    "is_already_present_recipient",
    "add_keyring_recipient_core",
    "add_space_keyring_recipient",
    "owner_ensure_keyring",
    "owner_ensure_space_keyring",
    "ensure_space_keyring_recipient",
    "open_encryptor",
    "build_encryptor",
    "read_profile",
    "read_profiles",
    "write_profile",
    "ensure_pseudo",
    "ensure_profile_keys",
]
