"""Pure-Python secp256k1 operations.

Provides exactly the two operations that ``starfish_identities.identity`` needs:

    schnorr_verify(pubkey_bytes, msg, sig) → bool
        BIP-340 Schnorr signature verification.

    ecdsa_recover_pubkey(digest, r, s, recid) → bytes
        Recover an uncompressed secp256k1 public key from an ECDSA signature.

No private-key operations.  Both surfaces work on public / wire data only.
Based on the BIP-340 reference implementation (public domain).

Internal representation
-----------------------
Points are ``(x: int, y: int)`` tuples; ``None`` represents the point at
infinity.  All arithmetic is in the prime field 𝔽ₚ; scalar multiplications
reduce scalars modulo the curve order *n*.
"""
from __future__ import annotations

import hashlib
from typing import Optional

# ── Curve constants ──────────────────────────────────────────────────────────

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_G: tuple[int, int] = (_GX, _GY)

# Pre-computed tag-hash prefix for BIP0340/challenge (avoids rehashing on each call).
_BIP340_CHALLENGE_TAG: bytes = hashlib.sha256(b"BIP0340/challenge").digest()
_BIP340_CHALLENGE_PREFIX: bytes = _BIP340_CHALLENGE_TAG + _BIP340_CHALLENGE_TAG

_Point = Optional[tuple[int, int]]


# ── Field / group arithmetic ─────────────────────────────────────────────────

def _point_add(P: _Point, Q: _Point) -> _Point:
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0]:
        if P[1] != Q[1]:
            return None  # P == −Q  →  infinity
        # Doubling: λ = 3x² / 2y
        lam = 3 * P[0] * P[0] * pow(2 * P[1], _P - 2, _P) % _P
    else:
        lam = (Q[1] - P[1]) * pow(Q[0] - P[0], _P - 2, _P) % _P
    x = (lam * lam - P[0] - Q[0]) % _P
    y = (lam * (P[0] - x) - P[1]) % _P
    return (x, y)


def _point_mul(P: _Point, k: int) -> _Point:
    """Left-to-right double-and-add scalar multiplication."""
    R: _Point = None
    while k:
        if k & 1:
            R = _point_add(R, P)
        P = _point_add(P, P)  # type: ignore[arg-type]
        k >>= 1
    return R


def _lift_x_even(x: int) -> _Point:
    """BIP-340 lift_x: return (x, y_even) for y² = x³+7 mod p, or None."""
    if x <= 0 or x >= _P:
        return None
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if pow(y, 2, _P) != y_sq:
        return None
    return (x, y if y % 2 == 0 else _P - y)


def _lift_x_parity(x: int, odd: bool) -> _Point:
    """Return (x, y) with the requested y-parity for y² = x³+7 mod p, or None."""
    if x <= 0 or x >= _P:
        return None
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if pow(y, 2, _P) != y_sq:
        return None
    if (y % 2 == 1) != odd:
        y = _P - y
    return (x, y)


# ── BIP-340 Schnorr verification ─────────────────────────────────────────────

def schnorr_verify(pubkey_bytes: bytes, msg: bytes, sig: bytes) -> bool:
    """BIP-340 Schnorr signature verification.

    Returns ``True`` iff ``sig`` is a valid BIP-340 signature of ``msg`` under
    ``pubkey_bytes``.  Returns ``False`` on any invalid input; **never raises**.

    Args:
        pubkey_bytes: 32-byte x-only secp256k1 public key (big-endian).
        msg: The message to verify (any length; Starfish passes 32-byte hashes).
        sig: 64-byte Schnorr signature ``r ‖ s`` (big-endian).
    """
    try:
        if len(pubkey_bytes) != 32 or len(sig) != 64:
            return False

        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")

        if r >= _P or s >= _N:
            return False

        P = _lift_x_even(int.from_bytes(pubkey_bytes, "big"))
        if P is None:
            return False

        # e = int(taggedHash("BIP0340/challenge", bytes(r) ‖ bytes(P) ‖ m)) mod n
        e = (
            int.from_bytes(
                hashlib.sha256(
                    _BIP340_CHALLENGE_PREFIX + sig[:32] + pubkey_bytes + msg
                ).digest(),
                "big",
            )
            % _N
        )

        # R = s·G − e·P  (subtract e·P by adding its negation)
        sG = _point_mul(_G, s)
        neg_eP: _Point = None
        if e > 0:
            eP = _point_mul(P, e)
            neg_eP = None if eP is None else (eP[0], _P - eP[1])
        R = _point_add(sG, neg_eP)

        return R is not None and R[1] % 2 == 0 and R[0] == r
    except Exception:  # noqa: BLE001
        return False


# ── ECDSA public-key recovery ────────────────────────────────────────────────

def ecdsa_recover_pubkey(digest: bytes, r: int, s: int, recid: int) -> bytes:
    """Recover the uncompressed secp256k1 public key from an ECDSA signature.

    Mirrors ``coincurve.PublicKey.from_signature_and_message(
        r‖s‖recid, digest, hasher=None).format(compressed=False)``.

    Args:
        digest: 32-byte pre-hashed message (``hasher=None`` convention).
        r: Signature *r* component (integer in ``[1, n)``).
        s: Signature *s* component (integer in ``[1, n)``).
        recid: Recovery ID, 0 or 1.

    Returns:
        65-byte uncompressed public key ``0x04 ‖ X(32) ‖ Y(32)``.

    Raises:
        ValueError: On invalid inputs or a failed recovery.
    """
    if recid not in (0, 1):
        raise ValueError(f"recid must be 0 or 1, got {recid!r}")
    if not (1 <= r < _N):
        raise ValueError("r out of range [1, n)")
    if not (1 <= s < _N):
        raise ValueError("s out of range [1, n)")
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes")

    # Candidate R has x-coordinate = r.  For secp256k1, n < p so r + n > p for
    # any r ≥ 1, meaning j = recid >> 1 is always 0 — no second candidate needed.
    R = _lift_x_parity(r, odd=(recid & 1) == 1)
    if R is None:
        raise ValueError("cannot lift r to a curve point")

    # e = int(digest) mod n  (pre-hashed digest used directly)
    e = int.from_bytes(digest, "big") % _N

    # Q = r⁻¹ · (s·R − e·G)
    r_inv = pow(r, _N - 2, _N)  # Fermat's little theorem; n is prime
    sR = _point_mul(R, r_inv * s % _N)
    # −e·G = (n − e) mod n · G; skip the multiply when e = 0 (coefficient = 0)
    neg_e = (_N - e) % _N
    neg_eG = _point_mul(_G, r_inv * neg_e % _N) if neg_e else None
    Q = _point_add(sR, neg_eG)

    if Q is None:
        raise ValueError("recovered public key is point at infinity")

    return b"\x04" + Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big")


__all__ = ["schnorr_verify", "ecdsa_recover_pubkey"]
