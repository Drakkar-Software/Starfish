"""Generate suite-secp256k1-ecdh.json — secp256k1 ECDH (KEM) conformance.

Locks the ``secp256k1-schnorr`` suite's KEM so the TypeScript (``@noble/curves``)
and Python (``coincurve``) implementations are proven byte-identical, not just
self-consistent. The suite derives the shared secret as the **x-coordinate** of
``priv · lift_even(peerXOnly)`` (see the suite modules), which is parity-free and
ECDH-symmetric: ``derive(aPriv, bPub) == derive(bPriv, aPub)``.

Each case pins both directions of a key pair plus the expected shared secret. At
least one case uses a peer whose natural point is odd-y, so the even-y lift picks
the negation — a regression that flipped the parity convention would change the
shared x and break this vector.

Run:
    python3 tests/test-vectors/_generators/suite_secp256k1_ecdh.py
"""

from __future__ import annotations

import json
import pathlib

from coincurve import PrivateKey

from starfish_protocol.suites import get_suite

_SUITE = get_suite("secp256k1-schnorr")


def _xonly(priv_hex: str) -> str:
    return PrivateKey(bytes.fromhex(priv_hex)).public_key.format(compressed=True)[1:].hex()


def _natural_parity(priv_hex: str) -> str:
    """'even' or 'odd' — the real y-parity of priv·G (the byte the x-only form drops)."""
    prefix = PrivateKey(bytes.fromhex(priv_hex)).public_key.format(compressed=True)[0]
    return "even" if prefix == 0x02 else "odd"


# (aPriv, bPriv) fixtures — small/known scalars for reproducibility, chosen so at
# least one peer has odd natural y-parity (see the assert below).
_FIXTURES: list[tuple[str, str]] = [
    ("00" * 31 + "02", "00" * 31 + "03"),
    ("11" * 32, "22" * 32),
    ("deadbeef" * 8, "00" * 31 + "07"),
]


def main() -> None:
    cases = []
    saw_odd_peer = False
    for a_priv, b_priv in _FIXTURES:
        a_pub = _xonly(a_priv)
        b_pub = _xonly(b_priv)
        shared_ab = _SUITE.derive_shared_secret(a_priv, b_pub)
        shared_ba = _SUITE.derive_shared_secret(b_priv, a_pub)
        assert shared_ab == shared_ba, "ECDH not symmetric"
        if "odd" in (_natural_parity(a_priv), _natural_parity(b_priv)):
            saw_odd_peer = True
        cases.append(
            {
                "aPrivHex": a_priv,
                "aPubHex": a_pub,
                "aParity": _natural_parity(a_priv),
                "bPrivHex": b_priv,
                "bPubHex": b_pub,
                "bParity": _natural_parity(b_priv),
                "sharedHex": shared_ab.hex(),
            }
        )
    assert saw_odd_peer, "vector must include at least one odd-y peer to lock the lift"

    out = {
        "description": (
            "Cross-language conformance for the secp256k1-schnorr KEM (ECDH). The "
            "shared secret is the x-coordinate of priv·lift_even(peerXOnly); it is "
            "parity-free and symmetric, so derive(aPriv, bPub) == derive(bPriv, "
            "aPub). @noble (TS) and coincurve (Python) must agree byte-for-byte. "
            "At least one case uses an odd-y peer to lock the even-y lift."
        ),
        "alg": "secp256k1-schnorr",
        "cases": cases,
    }
    out_path = pathlib.Path(__file__).resolve().parents[1] / "suite-secp256k1-ecdh.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
