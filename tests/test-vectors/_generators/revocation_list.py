"""Generate revocation-list.json — signed revocation list.

Locks:
- RevocationList shape: { v, iss, revoked: [{sub, nonce, exp}, ...], generation, sig }
- Canonical signing input: stable_stringify(list minus `sig`).
- Ed25519 signature by root (iss).
- generation: monotonically increasing per-issuer counter; later generations
  supersede earlier ones.

Run:
    python3 tests/test-vectors/_generators/revocation_list.py
"""

from __future__ import annotations

import base64
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _common import ed_sign, ed_verify, load_fixture, stable_stringify  # noqa: E402


# Domain-separation tag — must equal the protocol's _REVOCATION_DOMAIN /
# REVOCATION_DOMAIN (revocation.py / revocation.ts). The cross-language vector
# tests fail loudly if it drifts (a mismatched tag → verify fails).
_REVOCATION_DOMAIN = "starfish-revlist-v1\n"


def _build(*, alice, revoked, generation):
    body = {
        "v": 1,
        "alg": "ed25519",
        "iss": alice.ed_pub.hex(),
        "issUserId": alice.user_id,
        "generation": generation,
        "revoked": revoked,
    }
    canonical = _REVOCATION_DOMAIN + stable_stringify(body)
    sig = ed_sign(alice.ed_priv, canonical.encode("utf-8"))
    assert ed_verify(alice.ed_pub, sig, canonical.encode("utf-8"))
    return {
        "list": {**body, "sig": base64.b64encode(sig).decode("ascii")},
        "canonicalSigningInput": canonical,
    }


def main() -> None:
    alice = load_fixture("alice_root")
    laptop = load_fixture("alice_dev_1")
    phone = load_fixture("alice_dev_2")

    # Two revoked entries: laptop and phone caps each get a serial revoked
    nonce_laptop = base64.b64encode(bytes.fromhex("00112233445566778899aabbccddeeff")).decode()
    nonce_phone  = base64.b64encode(bytes.fromhex("ffeeddccbbaa99887766554433221100")).decode()
    exp_far = 1_999_999_999

    gen1 = _build(
        alice=alice,
        revoked=[{"sub": laptop.ed_pub.hex(), "nonce": nonce_laptop, "exp": exp_far}],
        generation=1,
    )
    gen2 = _build(
        alice=alice,
        revoked=[
            {"sub": laptop.ed_pub.hex(), "nonce": nonce_laptop, "exp": exp_far},
            {"sub": phone.ed_pub.hex(),  "nonce": nonce_phone,  "exp": exp_far},
        ],
        generation=2,
    )

    # Forged: same body, tampered signature
    forged = dict(gen2["list"])
    forged["sig"] = base64.b64encode(b"\xee" * 64).decode("ascii")

    out = {
        "description": (
            "Cross-language vector for v3.0 signed revocation lists. Two sequential "
            "generations (gen2 supersedes gen1), plus a forged variant whose signature "
            "must fail verification."
        ),
        "issuer": {"edPub": alice.ed_pub.hex(), "userId": alice.user_id},
        "subjects": {
            "alice_dev_1": {"edPub": laptop.ed_pub.hex(), "nonce": nonce_laptop},
            "alice_dev_2": {"edPub": phone.ed_pub.hex(),  "nonce": nonce_phone},
        },
        "generations": {
            "1": gen1,
            "2": gen2,
        },
        "forged": {
            "list": forged,
            "canonicalSigningInput": gen2["canonicalSigningInput"],
            "expectVerify": False,
        },
    }

    out_path = pathlib.Path(__file__).resolve().parents[1] / "revocation-list.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
