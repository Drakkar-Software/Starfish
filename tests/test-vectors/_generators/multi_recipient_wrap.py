"""Generate multi-recipient-wrap.json — replaces group-crypto.json for v3.0.

New shape: each epoch's `wrappedKeys` is a *list* of entries, each carrying
`subKem`, `ephKem`, `ct`, `addedBy`, `addedSig`, `addedAt`. No per-epoch
issuerKem. Recipients find their entry by exact subKem match.

Wrap procedure (HPKE-DHKEM-style):
    shared = ECDH(ephPriv, recipient.kemPub)
    wrapKey = HKDF(shared, salt="starfish-wrap", info="starfish-wrap")
    ct = AES-256-GCM(wrapKey, iv=12B, plaintext=CEK)

addedSig procedure (audit trail):
    payload = stable_stringify({subKem, ephKem, ct, addedBy, addedAt, epoch})
    addedSig = base64( Ed25519(addedBy_priv, payload_utf8) )

Run:
    python3 tests/test-vectors/_generators/multi_recipient_wrap.py
"""

from __future__ import annotations

import base64
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _common import (  # noqa: E402
    deterministic_eph_key,
    ed_sign,
    hkdf,
    load_fixture,
    stable_stringify,
    unwrap_for_recipient,
    wrap_for_recipient,
)

CEK_FIXED = bytes.fromhex("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")


def _build_entry(*, adder, recipient, cek, epoch, added_at):
    iv = hkdf(cek + recipient.kem_pub, b"starfish-wrap-iv-vector", b"iv", length=12)
    eph_priv = deterministic_eph_key(cek, recipient.kem_pub)
    ct_b64, eph_pub = wrap_for_recipient(cek, recipient.kem_pub, eph_priv, iv)

    canonical = stable_stringify({
        "addedAt": added_at,
        "addedBy": adder.ed_pub.hex(),
        "ct": ct_b64,
        "ephKem": eph_pub.hex(),
        "epoch": epoch,
        "subKem": recipient.kem_pub.hex(),
    })
    added_sig = ed_sign(adder.ed_priv, canonical.encode("utf-8"))

    return {
        "subKem": recipient.kem_pub.hex(),
        "ephKem": eph_pub.hex(),
        "ct": ct_b64,
        "addedBy": adder.ed_pub.hex(),
        "addedSig": base64.b64encode(added_sig).decode("ascii"),
        "addedAt": added_at,
    }


def main() -> None:
    alice_root = load_fixture("alice_root")
    alice_laptop = load_fixture("alice_dev_1")
    alice_phone = load_fixture("alice_dev_2")
    bob = load_fixture("bob_root")

    added_at = 1_747_000_000
    epoch = 1
    cek_hex = CEK_FIXED.hex()

    # Recipients in epoch 1: Alice's two devices + Bob (member of shared-notes).
    entries = [
        _build_entry(adder=alice_root, recipient=r, cek=CEK_FIXED, epoch=epoch, added_at=added_at)
        for r in (alice_laptop, alice_phone, bob)
    ]

    keyring = {
        "v": 1,
        "currentEpoch": epoch,
        "epochs": {
            str(epoch): {
                "wrappedKeys": entries,
                "createdAt": added_at,
            },
        },
    }

    # Verify each recipient can unwrap.
    expected_cek = cek_hex
    for recip, entry in zip((alice_laptop, alice_phone, bob), entries):
        recovered = unwrap_for_recipient(
            entry["ct"], recip.kem_priv, bytes.fromhex(entry["ephKem"])
        )
        assert recovered.hex() == expected_cek, f"unwrap failed for {recip.label}"

    out = {
        "description": (
            "Cross-language vector for v3.0 multi-recipient key wrapping (replaces "
            "group-crypto.json). Each wrappedKeys entry uses per-entry ephemeral "
            "ECDH (HPKE-DHKEM-style); recipients identified by exact `subKem` match; "
            "each entry signed by the adder for audit. Three recipients: two devices "
            "of Alice plus Bob as a member of the shared collection."
        ),
        "constants": {
            "wrapSaltUtf8": "starfish-wrap",
            "wrapInfoUtf8": "starfish-wrap",
            "ivBytes": 12,
            "addedSigCanonicalKeys": ["addedAt", "addedBy", "ct", "ephKem", "epoch", "subKem"],
        },
        "fixtures": {
            "alice_root":    alice_root.as_dict(),
            "alice_dev_1":   alice_laptop.as_dict(),
            "alice_dev_2":   alice_phone.as_dict(),
            "bob_root":      bob.as_dict(),
        },
        "cek": cek_hex,
        "keyring": keyring,
        "unwrapChecks": [
            {"recipient": "alice_dev_1", "expectedCek": expected_cek},
            {"recipient": "alice_dev_2", "expectedCek": expected_cek},
            {"recipient": "bob_root",    "expectedCek": expected_cek},
        ],
    }

    out_path = pathlib.Path(__file__).resolve().parents[1] / "multi-recipient-wrap.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
