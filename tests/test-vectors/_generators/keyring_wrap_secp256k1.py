"""Generate keyring-wrap-secp256k1.json — secp256k1 KEM keyring wrap vector.

Locks the suite-aware keyring wrap so @noble (TS) and coincurve (Python) produce
byte-identical `WrappedKeyEntry`s for a secp256k1 recipient. Drives the REAL
`starfish_keyring.wrap_for_recipient` (not a re-implementation) with a fixed
ephemeral key + IV so the entry is reproducible across runs and languages.

Two cases lock the two tolerant-reader combinations involving secp256k1:
  1. secp256k1 adder + secp256k1 recipient  → kemAlg + addedByAlg BOTH present.
  2. ed25519 adder  + secp256k1 recipient    → kemAlg present, addedByAlg absent
     (the mixed-suite owner-seals-to-Nostr-member case).

The X25519 case stays in multi-recipient-wrap.json (unchanged = no-drift proof).

Run:
    python3 tests/test-vectors/_generators/keyring_wrap_secp256k1.py
"""

from __future__ import annotations

import json
import pathlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from starfish_keyring.keyring import (
    WrappedKeyEntry,
    unwrap_from_entry,
    verify_entry_signature,
    wrap_for_recipient,
)
from starfish_protocol.suites import get_suite

_SECP = get_suite("secp256k1-schnorr")

_CEK = bytes.fromhex("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
_IV = bytes.fromhex("0102030405060708090a0b0c")
_EPH_PRIV = (7).to_bytes(32, "big")  # deterministic ephemeral secp scalar
_EPOCH = 1
_ADDED_AT = 1_747_000_000


def _secp_keys(priv_int: int) -> tuple[str, str]:
    priv_hex = (priv_int).to_bytes(32, "big").hex()
    return priv_hex, _SECP.kem_public(priv_hex)


def _ed_keys(seed_byte: int) -> tuple[str, str]:
    priv = Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)
    priv_hex = priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    ).hex()
    pub_hex = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return priv_hex, pub_hex


def _case(*, label, adder_priv, adder_pub, added_by_alg, recipient_priv, recipient_pub):
    entry = wrap_for_recipient(
        _CEK,
        recipient_pub,
        adder_ed_priv_hex=adder_priv,
        adder_ed_pub_hex=adder_pub,
        added_at=_ADDED_AT,
        epoch=_EPOCH,
        kem_alg="secp256k1-schnorr",
        added_by_alg=added_by_alg,
        eph_priv=_EPH_PRIV,
        iv=_IV,
    )
    assert verify_entry_signature(entry, _EPOCH), "self-verify failed"
    assert unwrap_from_entry(entry, recipient_priv) == _CEK, "self-unwrap failed"
    return {
        "label": label,
        "adderPrivHex": adder_priv,
        "adderPubHex": adder_pub,
        "addedByAlg": added_by_alg,
        "recipientKemPrivHex": recipient_priv,
        "recipientKemPubHex": recipient_pub,
        "kemAlg": "secp256k1-schnorr",
        "ephPrivHex": _EPH_PRIV.hex(),
        "ivHex": _IV.hex(),
        "epoch": _EPOCH,
        "addedAt": _ADDED_AT,
        "entry": entry.to_dict(),
    }


def _negative(label: str, base_entry: dict, mutate) -> dict:
    """A tampered copy of ``base_entry`` that MUST fail verification.

    ``mutate`` receives a deep-ish copy of the signed entry dict and edits it in
    place — stripping a present alg tag or swapping it. The original ``addedSig``
    is left untouched, so verification fails because the canonical signing input
    (or the dispatched suite) no longer matches the signed bytes. Both languages
    feed ``entry`` straight into verify and assert ``False`` — proving the
    downgrade guard cross-language, not just per-implementation.
    """
    entry = dict(base_entry)
    mutate(entry)
    # Self-check at generation time: the guard must reject this entry.
    assert verify_entry_signature(WrappedKeyEntry.from_dict(entry), _EPOCH) is False, (
        f"negative case {label!r} unexpectedly verified — guard is not catching it"
    )
    return {"label": label, "epoch": _EPOCH, "expectVerify": False, "entry": entry}


def _strip(field: str):
    def m(e: dict) -> None:
        e.pop(field, None)

    return m


def _swap(field: str, value: str):
    def m(e: dict) -> None:
        e[field] = value

    return m


def main() -> None:
    secp_adder_priv, secp_adder_pub = _secp_keys(9)
    rcpt_priv, rcpt_pub = _secp_keys(5)
    ed_adder_priv, ed_adder_pub = _ed_keys(0x42)

    cases = [
        _case(
            label="secp256k1 adder + secp256k1 recipient",
            adder_priv=secp_adder_priv,
            adder_pub=secp_adder_pub,
            added_by_alg="secp256k1-schnorr",
            recipient_priv=rcpt_priv,
            recipient_pub=rcpt_pub,
        ),
        _case(
            label="ed25519 adder + secp256k1 recipient (mixed)",
            adder_priv=ed_adder_priv,
            adder_pub=ed_adder_pub,
            added_by_alg="ed25519",
            recipient_priv=rcpt_priv,
            recipient_pub=rcpt_pub,
        ),
    ]

    # Base for the downgrade canaries: case 1 carries BOTH tags present
    # (kemAlg + addedByAlg = secp256k1-schnorr), so each strip/swap is detectable.
    both_tags = cases[0]["entry"]
    negative_cases = [
        _negative("strip kemAlg (downgrade) → fails verify", both_tags, _strip("kemAlg")),
        _negative("strip addedByAlg (downgrade) → fails verify", both_tags, _strip("addedByAlg")),
        _negative(
            "swap addedByAlg to ed25519 → fails verify",
            both_tags,
            _swap("addedByAlg", "ed25519"),
        ),
        _negative(
            "swap kemAlg to ed25519 → fails verify", both_tags, _swap("kemAlg", "ed25519")
        ),
        _negative(
            'empty-string addedByAlg ("" must NOT default to ed25519) → fails verify',
            both_tags,
            _swap("addedByAlg", ""),
        ),
    ]

    out = {
        "description": (
            "Cross-language vector for the secp256k1 KEM keyring wrap. Each case "
            "drives the real suite-aware wrap_for_recipient with a fixed ephemeral "
            "key + IV; @noble (TS) and coincurve (Python) must produce a byte-"
            "identical WrappedKeyEntry, whose addedSig verifies and whose CEK "
            "unwraps. Case 1 carries both kemAlg + addedByAlg; case 2 (ed25519 "
            "adder) carries kemAlg only (addedByAlg absent, tolerant reader). "
            "negativeCases tamper with case 1's signed entry (strip/swap the "
            "kemAlg/addedByAlg tags); both languages MUST reject each one "
            "(expectVerify=false), proving the downgrade guard cross-language."
        ),
        "constants": {
            "wrapSaltUtf8": "starfish-wrap",
            "secp256k1WrapInfoUtf8": "starfish-wrap:secp256k1-schnorr",
            "ivBytes": 12,
        },
        "cek": _CEK.hex(),
        "cases": cases,
        "negativeCases": negative_cases,
    }
    out_path = pathlib.Path(__file__).resolve().parents[1] / "keyring-wrap-secp256k1.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
