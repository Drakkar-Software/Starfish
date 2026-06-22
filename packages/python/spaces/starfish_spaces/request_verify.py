"""kemSig — Ed25519 signature of a KEM public key.

When an identity shares its KEM public key (e.g. in a join-request or profile),
the receiver must verify that the sender actually owns that KEM key — otherwise a
MITM could substitute their own KEM key and intercept sealed messages.  The kemSig
is produced by signing the raw KEM-pub bytes with the sender's Ed25519 private key;
the verifier checks the signature against the sender's known Ed25519 public key.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def sign_kem_sig(kem_pub: str, ed_priv: str) -> str:
    """Sign ``kem_pub`` with ``ed_priv``, returning the signature as lowercase hex.

    Args:
        kem_pub: The KEM public key to sign (hex).
        ed_priv: The Ed25519 private key to sign with (hex).

    Returns:
        Ed25519 signature of the raw ``kem_pub`` bytes, hex-encoded (lowercase).
    """
    msg = bytes.fromhex(kem_pub)
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ed_priv))
    sig_bytes = priv.sign(msg)
    return sig_bytes.hex()


def verify_kem_sig(
    ed_pub: str,
    kem_pub: str,
    kem_sig: str | None,
) -> bool:
    """Verify that ``kem_sig`` is a valid Ed25519 signature of ``kem_pub`` by ``ed_pub``.

    Returns ``False`` (does NOT raise) when ``kem_sig`` is absent or malformed.

    Args:
        ed_pub: Signer's Ed25519 public key (hex).
        kem_pub: The KEM public key whose signature is being verified (hex).
        kem_sig: The signature to verify (hex), or ``None`` / ``""`` for absent.

    Returns:
        ``True`` if the signature is valid; ``False`` otherwise.
    """
    if not kem_sig:
        return False
    try:
        sig_bytes = bytes.fromhex(kem_sig)
        msg = bytes.fromhex(kem_pub)
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(ed_pub))
        pub.verify(sig_bytes, msg)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


__all__ = ["sign_kem_sig", "verify_kem_sig"]
