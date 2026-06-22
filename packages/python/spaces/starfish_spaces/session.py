"""Session abstraction.

A :class:`Session` is the root runtime object threaded through all spaces domain
calls.  It holds the identity (userId + device keys), the pre-built Starfish
clients (content, account, spaces-registry, spaces-keyring), and the resolved
:class:`SpaceLayout` + namespace constants.

Build sessions with:

- :func:`build_session` — from a root-derived ``(userId, keys)`` pair.
- :func:`build_linked_session` — from a paired device's ``(userId, keys, capCert)`` triple.
- :func:`derive_session` — from a 12-word BIP-39 seed phrase (derives the root identity first).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Optional, TYPE_CHECKING

from starfish_identities import bootstrap_root_identity, mint_device_cap, compute_owner_trusted_adders

from starfish_spaces.client import (
    ClientOpts,
    DeviceKeys,
    ensure_profile_keys,
    ensure_pseudo,
    make_space_client,
)
from starfish_spaces.config import KvAdapter, SpaceLayout, SpacesConfig, get_spaces_config
from starfish_spaces.layout import default_space_layout, default_user_id_from_ed_pub

if TYPE_CHECKING:
    from starfish_sdk import StarfishClient

# ── Session ───────────────────────────────────────────────────────────────────


@dataclass
class Session:
    """Root runtime object for all spaces domain operations."""

    # ── Identity ──────────────────────────────────────────────────────────────
    user_id: str
    name: str
    keys: DeviceKeys
    content_cap: Any
    account_cap: Any

    # ── Pre-built clients ─────────────────────────────────────────────────────
    content_client: "StarfishClient"
    """Primary client for space content (keyrings, nodes, objects)."""

    account_client: "StarfishClient"
    """Client for account-scoped docs (profile, ``_spaces`` registry)."""

    spaces_registry_client: "StarfishClient"
    """Client for the cross-app spaces registry."""

    spaces_keyring_client: "StarfishClient"
    """Client for cross-app space-keyring operations."""

    # ── Display metadata ──────────────────────────────────────────────────────
    fingerprint: str
    owner_ed_pub: str
    """Ed25519 pubkey that OWNS this session's spaces (trusted-adder anchor)."""

    # ── Resolved configuration ────────────────────────────────────────────────
    layout: SpaceLayout
    user_id_from_ed_pub: Callable[[str], Coroutine[Any, Any, str]]
    space_id_prefix: str
    node_id_prefix: str
    inbox_aad_namespace: str
    kv_key_prefix: str
    kv_adapter: Optional[KvAdapter] = None

    # ── Server coordinates (for raw-fetch helpers) ────────────────────────────
    base_url: str = ""
    namespace: str = ""


# ── Config resolution ─────────────────────────────────────────────────────────


def _resolve_config(cfg: SpacesConfig) -> dict[str, Any]:
    return {
        "layout": cfg.layout or default_space_layout,
        "user_id_from_ed_pub": cfg.user_id_from_ed_pub or default_user_id_from_ed_pub,
        "space_id_prefix": cfg.space_id_prefix or "sp-",
        "node_id_prefix": cfg.node_id_prefix or "obj-",
        "inbox_aad_namespace": cfg.inbox_aad_namespace or "starfish:inbox:v1",
        "kv_key_prefix": cfg.kv_key_prefix or "starfish.spaceaccess.",
        "kv_adapter": cfg.kv_adapter,
    }


# ── Public helpers ────────────────────────────────────────────────────────────


def fingerprint_from_user_id(user_id: str) -> str:
    """Human-readable fingerprint from a userId hex string."""
    h = "".join(c for c in user_id if c in "0123456789abcdefABCDEF").upper()
    parts = [h[0:4], h[4:8], h[8:12]]
    return " · ".join(p for p in parts if p)


def generate_seed_words() -> list[str]:
    """Fresh 12-word BIP-39 recovery seed phrase."""
    try:
        from mnemonic import Mnemonic
        mnemo = Mnemonic("english")
        return mnemo.generate(128).split()
    except ImportError as exc:
        raise ImportError(
            "The 'mnemonic' package is required for BIP-39 support. "
            "Install it with: pip install mnemonic>=0.21"
        ) from exc


def is_valid_seed(words: list[str]) -> bool:
    """Return ``True`` when ``words`` is a valid BIP-39 mnemonic."""
    try:
        from mnemonic import Mnemonic
        mnemo = Mnemonic("english")
        return mnemo.check(" ".join(words).strip())
    except Exception:
        return False


def owner_trusted_adders(session: Session) -> list[str]:
    """Trusted-adder allow-list for opening an OWNED space's keyring."""
    return compute_owner_trusted_adders(session.owner_ed_pub, session.keys["edPub"])


# ── Build helpers ─────────────────────────────────────────────────────────────


@dataclass
class BuildSessionOpts:
    """Arguments for :func:`build_session`."""

    user_id: str
    keys: DeviceKeys
    client_opts: ClientOpts
    name: Optional[str] = None
    shared_namespace: Optional[str] = None
    config: Optional[SpacesConfig] = None


@dataclass
class LinkedIdentity:
    """A paired device's credentials."""

    user_id: str
    keys: DeviceKeys
    cap_cert: Any


@dataclass
class BuildLinkedSessionOpts:
    """Arguments for :func:`build_linked_session`."""

    identity: LinkedIdentity
    client_opts: ClientOpts
    name: Optional[str] = None
    shared_namespace: Optional[str] = None
    config: Optional[SpacesConfig] = None


async def build_session(opts: BuildSessionOpts) -> Session:
    """Build a full owner session from a root-derived ``(user_id, keys)`` pair.

    Mints two device caps (content + account), constructs four clients, and
    writes/confirms the display name and profile keys.
    """
    merged_cfg = SpacesConfig()
    if opts.config:
        merged_cfg = opts.config
    else:
        merged_cfg = get_spaces_config()

    resolved = _resolve_config(merged_cfg)
    layout: SpaceLayout = resolved["layout"]

    keys = opts.keys
    user_id = opts.user_id
    client_opts = opts.client_opts

    sub = {"edPubHex": keys["edPub"], "kemPubHex": keys["kemPub"]}
    content_cap = mint_device_cap(keys["edPriv"], keys["edPub"], sub, layout.owner_scope())
    account_cap = mint_device_cap(
        keys["edPriv"], keys["edPub"], sub, layout.account_scope(user_id)
    )

    content_client = make_space_client(content_cap, keys["edPriv"], client_opts)
    account_client = make_space_client(account_cap, keys["edPriv"], client_opts)

    shared_opts: Optional[ClientOpts] = None
    if opts.shared_namespace:
        shared_opts = {**client_opts, "namespace": opts.shared_namespace}  # type: ignore[misc]

    spaces_registry_client = (
        make_space_client(account_cap, keys["edPriv"], shared_opts)
        if shared_opts
        else account_client
    )
    spaces_keyring_client = (
        make_space_client(content_cap, keys["edPriv"], shared_opts)
        if shared_opts
        else content_client
    )

    fallback = (opts.name or "").strip() or f"user-{user_id[:6]}"
    try:
        display_name = await ensure_pseudo(account_client, user_id, layout, fallback)
    except Exception:
        display_name = fallback

    try:
        await ensure_profile_keys(account_client, user_id, layout, keys)
    except Exception:
        pass

    return Session(
        user_id=user_id,
        name=display_name,
        keys=keys,
        content_cap=content_cap,
        account_cap=account_cap,
        content_client=content_client,
        account_client=account_client,
        spaces_registry_client=spaces_registry_client,
        spaces_keyring_client=spaces_keyring_client,
        fingerprint=fingerprint_from_user_id(user_id),
        owner_ed_pub=keys["edPub"],
        layout=layout,
        user_id_from_ed_pub=resolved["user_id_from_ed_pub"],
        space_id_prefix=resolved["space_id_prefix"],
        node_id_prefix=resolved["node_id_prefix"],
        inbox_aad_namespace=resolved["inbox_aad_namespace"],
        kv_key_prefix=resolved["kv_key_prefix"],
        kv_adapter=resolved["kv_adapter"],
        base_url=client_opts.get("baseUrl", ""),
        namespace=client_opts.get("namespace", ""),
    )


async def build_linked_session(opts: BuildLinkedSessionOpts) -> Session:
    """Build a session for a paired (linked) device.

    The device keypair is NOT the root, so it cannot self-mint caps — all four
    clients use the root-signed ``cap_cert`` from the pairing bundle.
    """
    merged_cfg = opts.config or get_spaces_config()
    resolved = _resolve_config(merged_cfg)
    layout: SpaceLayout = resolved["layout"]

    identity = opts.identity
    keys = identity.keys
    user_id = identity.user_id
    cap_cert = identity.cap_cert
    client_opts = opts.client_opts

    content_client = make_space_client(cap_cert, keys["edPriv"], client_opts)
    account_client = make_space_client(cap_cert, keys["edPriv"], client_opts)

    shared_opts: Optional[ClientOpts] = None
    if opts.shared_namespace:
        shared_opts = {**client_opts, "namespace": opts.shared_namespace}  # type: ignore[misc]

    spaces_registry_client = (
        make_space_client(cap_cert, keys["edPriv"], shared_opts)
        if shared_opts
        else account_client
    )
    spaces_keyring_client = (
        make_space_client(cap_cert, keys["edPriv"], shared_opts)
        if shared_opts
        else content_client
    )

    fallback = (opts.name or "").strip() or f"user-{user_id[:6]}"
    try:
        display_name = await ensure_pseudo(account_client, user_id, layout, fallback)
    except Exception:
        display_name = fallback

    # issuer of the cap-cert is the owner's root edPub
    owner_ed_pub = cap_cert.get("iss", keys["edPub"]) if isinstance(cap_cert, dict) else keys["edPub"]

    return Session(
        user_id=user_id,
        name=display_name,
        keys=keys,
        content_cap=cap_cert,
        account_cap=cap_cert,
        content_client=content_client,
        account_client=account_client,
        spaces_registry_client=spaces_registry_client,
        spaces_keyring_client=spaces_keyring_client,
        fingerprint=fingerprint_from_user_id(user_id),
        owner_ed_pub=owner_ed_pub,
        layout=layout,
        user_id_from_ed_pub=resolved["user_id_from_ed_pub"],
        space_id_prefix=resolved["space_id_prefix"],
        node_id_prefix=resolved["node_id_prefix"],
        inbox_aad_namespace=resolved["inbox_aad_namespace"],
        kv_key_prefix=resolved["kv_key_prefix"],
        kv_adapter=resolved["kv_adapter"],
        base_url=client_opts.get("baseUrl", ""),
        namespace=client_opts.get("namespace", ""),
    )


async def derive_session(
    seed_words: list[str],
    client_opts: ClientOpts,
    name: Optional[str] = None,
    shared_namespace: Optional[str] = None,
    config: Optional[SpacesConfig] = None,
) -> Session:
    """Derive a full owner session from a 12-word BIP-39 seed phrase.

    Runs :func:`bootstrap_root_identity` (Argon2id — slow) to derive the root
    identity, then calls :func:`build_session`.
    """
    passphrase = " ".join(seed_words).strip()
    creds = bootstrap_root_identity(passphrase)
    return await build_session(
        BuildSessionOpts(
            user_id=creds.user_id,
            keys=creds.device,  # type: ignore[arg-type]
            name=name,
            client_opts=client_opts,
            shared_namespace=shared_namespace,
            config=config,
        )
    )


__all__ = [
    "Session",
    "BuildSessionOpts",
    "LinkedIdentity",
    "BuildLinkedSessionOpts",
    "fingerprint_from_user_id",
    "generate_seed_words",
    "is_valid_seed",
    "owner_trusted_adders",
    "build_session",
    "build_linked_session",
    "derive_session",
]
