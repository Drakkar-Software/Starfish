"""Generate suite-secp256k1.json — BIP-340 Schnorr sign/verify conformance.

Locks the ``secp256k1-schnorr`` suite's signatures so the TypeScript
(``@noble/curves``) and Python (``coincurve``) implementations are proven
byte-identical, not just self-consistent. The suite signs ``sha256(message)``
with deterministic ``aux_rand = 0`` (see the suite modules), so every signature
here is reproducible across runs and languages.

Run:
    python3 tests/test-vectors/_generators/suite_secp256k1.py
"""

from __future__ import annotations

import base64
import json
import pathlib

from coincurve import PublicKeyXOnly

from starfish_protocol.suites import get_suite

_SUITE = get_suite("secp256k1-schnorr")

# (private-key hex, message) fixtures. Private keys are small fixed scalars so
# the vector is reproducible; messages cover empty, ascii, and a canonical-ish
# JSON blob (the real signing inputs are stable_stringify outputs).
_FIXTURES: list[tuple[str, bytes]] = [
    ("00" * 31 + "03", b"hello starfish"),
    ("00" * 31 + "03", b""),
    ("11" * 32, b'{"alg":"secp256k1-schnorr","m":"GET"}'),
    ("deadbeef" * 8, b"the quick brown fox"),
]


def main() -> None:
    cases = []
    for priv_hex, message in _FIXTURES:
        pub_hex = PublicKeyXOnly.from_secret(bytes.fromhex(priv_hex)).format().hex()
        sig = _SUITE.sign(message, priv_hex)
        assert _SUITE.verify(sig, message, pub_hex), "self-verify failed"
        cases.append(
            {
                "privHex": priv_hex,
                "pubHex": pub_hex,
                "messageUtf8": message.decode("utf-8"),
                "signatureHex": sig.hex(),
                "expectVerify": True,
            }
        )

    # Negative: a tampered signature (last byte flipped) must NOT verify.
    base = cases[0]
    bad = bytearray(bytes.fromhex(base["signatureHex"]))
    bad[-1] ^= 0x01
    cases.append(
        {
            "privHex": base["privHex"],
            "pubHex": base["pubHex"],
            "messageUtf8": base["messageUtf8"],
            "signatureHex": bytes(bad).hex(),
            "expectVerify": False,
        }
    )

    out = {
        "description": (
            "Cross-language conformance for the secp256k1-schnorr suite. Locks "
            "BIP-340 Schnorr signatures over sha256(message) with deterministic "
            "aux_rand=0, so @noble (TS) and coincurve (Python) must produce and "
            "verify byte-identical signatures. Includes a tampered-signature "
            "negative case."
        ),
        "alg": "secp256k1-schnorr",
        "cases": cases,
    }
    out_path = pathlib.Path(__file__).resolve().parents[1] / "suite-secp256k1.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
