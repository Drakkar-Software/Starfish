"""Shared KEM helper for the suite implementations."""

from __future__ import annotations


def assert_usable_shared_secret(secret: bytes) -> None:
    """Reject an all-zero KEM shared secret. For X25519 this catches the
    low-order point attack (RFC 7748 §6.1); for secp256k1 a valid point never
    has an all-zero x-coordinate, so a zero result means a degenerate input
    slipped through. Either way the wrap key would be predictable — fail closed.
    """
    if not any(secret):
        raise ValueError("Rejected zero KEM shared secret (degenerate point)")
