"""Per-node keyring helpers (E2EE for invite-node encryption).

Thin wrappers over :mod:`starfish_spaces.client` keyring helpers specialised to
the node-keyring path.  INVARIANT: ensure the keyring exists before adding a
recipient.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional, TypedDict

from starfish_keyring import remove_recipient
from starfish_identities import compute_owner_trusted_adders

from starfish_spaces.client import (
    DeviceKeys,
    add_keyring_recipient_core,
    build_encryptor,
    open_encryptor,
    owner_ensure_keyring,
)

if TYPE_CHECKING:
    from starfish_sdk import StarfishClient
    from starfish_spaces.config import SpaceLayout
    from starfish_spaces.session import Session


# ── Types ─────────────────────────────────────────────────────────────────────


class NodeKeyringRecipient(TypedDict, total=False):
    """A recipient to add/remove from a per-node keyring."""

    subKem: str
    userId: Optional[str]
    label: Optional[str]


# ── Internal helper ───────────────────────────────────────────────────────────


def _adder_of(session: "Session") -> dict[str, str]:
    return {
        "edPriv": session.keys["edPriv"],
        "edPub": session.keys["edPub"],
        "kemPriv": session.keys["kemPriv"],
    }


# ── Public API ────────────────────────────────────────────────────────────────


async def owner_ensure_node_keyring(
    client: "StarfishClient",
    session: "Session",
    space_id: str,
    node_id: str,
    layout: "SpaceLayout",
) -> None:
    """Ensure the per-node keyring exists and the owner is in it.

    CAS-safe (retries on conflict via :func:`owner_ensure_keyring`).
    """
    trusted = owner_trusted_adders(session)
    await owner_ensure_keyring(
        client,
        session.keys,  # type: ignore[arg-type]
        layout.node_keyring_name(space_id, node_id),
        layout.node_keyring_pull(space_id, node_id),
        layout.node_keyring_push(space_id, node_id),
        trusted_adders=trusted,
    )


async def open_node_encryptor(
    client: "StarfishClient",
    session: "Session",
    space_id: str,
    node_id: str,
    layout: "SpaceLayout",
) -> Any:
    """Open an encryptor for the per-node keyring (raises :class:`SpaceAccessError` on failure)."""
    trusted = owner_trusted_adders(session)
    return await open_encryptor(
        client,
        layout.node_keyring_name(space_id, node_id),
        session.keys["kemPriv"],
        trusted_adders=trusted,
        space_id=space_id,
        node_id=node_id,
    )


async def build_node_encryptor(
    client: "StarfishClient",
    session: "Session",
    space_id: str,
    node_id: str,
    layout: "SpaceLayout",
) -> Optional[Any]:
    """Like :func:`open_node_encryptor` but returns ``None`` instead of raising."""
    trusted = owner_trusted_adders(session)
    return await build_encryptor(
        client,
        layout.node_keyring_name(space_id, node_id),
        session.keys["kemPriv"],
        trusted_adders=trusted,
        space_id=space_id,
        node_id=node_id,
    )


async def add_node_keyring_recipient(
    client: "StarfishClient",
    session: "Session",
    space_id: str,
    node_id: str,
    recipient: NodeKeyringRecipient,
    layout: "SpaceLayout",
) -> None:
    """Add ``recipient`` to the per-node keyring."""
    trusted = owner_trusted_adders(session)
    await add_keyring_recipient_core(
        client,
        layout.node_keyring_name(space_id, node_id),
        dict(recipient),
        _adder_of(session),
        trusted_adders=trusted,
    )


async def ensure_node_keyring_recipient(
    client: "StarfishClient",
    session: "Session",
    space_id: str,
    node_id: str,
    recipient: NodeKeyringRecipient,
    layout: "SpaceLayout",
) -> None:
    """Ensure the node keyring exists, then add ``recipient``."""
    await owner_ensure_node_keyring(client, session, space_id, node_id, layout)
    await add_node_keyring_recipient(client, session, space_id, node_id, recipient, layout)


async def remove_node_keyring_recipient(
    client: "StarfishClient",
    session: "Session",
    space_id: str,
    node_id: str,
    sub_kem: str,
    layout: "SpaceLayout",
) -> None:
    """Remove ``sub_kem`` from the per-node keyring (forward secrecy via epoch rotation).

    Removes and rotates the keyring epoch so the removed recipient cannot decrypt
    future content even if they retained the old CEK.
    """
    trusted = owner_trusted_adders(session)
    await remove_recipient(
        client,
        layout.node_keyring_name(space_id, node_id),
        [sub_kem],
        _adder_of(session),  # type: ignore[arg-type]
        trusted_adders=trusted,
    )


def owner_trusted_adders(session: "Session") -> list[str]:
    """Return the trusted-adder allow-list for a session opening its own keyring."""
    return compute_owner_trusted_adders(session.owner_ed_pub, session.keys["edPub"])


__all__ = [
    "NodeKeyringRecipient",
    "owner_ensure_node_keyring",
    "open_node_encryptor",
    "build_node_encryptor",
    "add_node_keyring_recipient",
    "ensure_node_keyring_recipient",
    "remove_node_keyring_recipient",
    "owner_trusted_adders",
    "compute_owner_trusted_adders",
]
