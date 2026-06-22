"""Trusted-adder allow-list helpers.

When opening a keyring, the caller must supply the set of Ed25519 pubkeys whose
``addedBy`` signatures are trusted for CEK-wrap entries. This module derives that
list from the ownership relationship between a device and the space owner.
"""

from __future__ import annotations


def compute_owner_trusted_adders(
    owner_ed_pub: str | None,
    self_ed_pub: str,
) -> list[str]:
    """Return the trusted-adder allow-list for a device opening an owned space's keyring.

    For the root device (or any device where ``owner_ed_pub`` equals ``self_ed_pub``),
    only ``self_ed_pub`` is trusted — no external adder needs to be in the list.

    For a paired/linked device, the space was created by the root (``owner_ed_pub``)
    and the linked device's own key (``self_ed_pub``) was added later.  Both must be
    trusted so the device can read both the original root-added entries and any
    entries added after it joined.

    Args:
        owner_ed_pub: Ed25519 pubkey (hex) of the space owner (root). When ``None``,
            defaults to ``self_ed_pub`` (treats device as its own owner).
        self_ed_pub: Ed25519 pubkey (hex) of this device.

    Returns:
        ``[self_ed_pub]`` when ``owner_ed_pub`` equals (or defaults to) ``self_ed_pub``,
        otherwise ``[owner_ed_pub, self_ed_pub]``.
    """
    owner = owner_ed_pub if owner_ed_pub is not None else self_ed_pub
    return [owner, self_ed_pub] if owner != self_ed_pub else [self_ed_pub]


__all__ = ["compute_owner_trusted_adders"]
