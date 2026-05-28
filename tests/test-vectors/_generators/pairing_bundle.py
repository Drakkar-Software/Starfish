"""Generate pairing-bundle.json — QR payload + cap-cert + wrapped CEKs roundtrip.

Models the in-person QR pairing flow:
  1. New device generates its keypair and shows a QR payload.
  2. Root device scans, mints a `kind: "device"` cap-cert for the new device,
     and wraps every accessible collection's current CEK for the device's KEM key.
  3. Root device hands back the bundle.
  4. New device installs: verifies cap-cert, unwraps CEKs.

Locks the canonical encodings + base64url QR payload encoding.

Run:
    python3 tests/test-vectors/_generators/pairing_bundle.py
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
    ed_verify,
    hkdf,
    load_fixture,
    stable_stringify,
    unwrap_for_recipient,
    wrap_for_recipient,
)


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def main() -> None:
    alice = load_fixture("alice_root")
    new_device = load_fixture("alice_dev_2")  # treat alice_dev_2 as the "new" device being paired

    # Step 1: QR payload from new device → root device
    qr_nonce = bytes.fromhex("0123456789abcdef0123456789abcdef")
    qr_payload_obj = {
        "v": 1,
        "devEdPub": new_device.ed_pub.hex(),
        "devKemPub": new_device.kem_pub.hex(),
        "requestedScope": {
            "ops": ["read", "write", "list"],
            "collections": ["notes", "tasks"],
            "paths": [
                "notes/" + alice.user_id + "/*",
                "tasks/" + alice.user_id + "/*",
            ],
        },
        "qrNonce": base64.b64encode(qr_nonce).decode("ascii"),
    }
    qr_payload_canonical = stable_stringify(qr_payload_obj)
    qr_payload_b64url = _b64url(qr_payload_canonical.encode("utf-8"))

    # Step 2a: Root mints a device cap-cert for the new device.
    nbf = 1_747_000_000
    exp = nbf + 30 * 24 * 3600
    cert_nonce = base64.b64encode(bytes.fromhex("abcdef0123456789abcdef0123456789")).decode()

    cert_body = {
        "v": 1,
        "kind": "device",
        "iss": alice.ed_pub.hex(),
        "issUserId": alice.user_id,
        "sub": new_device.ed_pub.hex(),
        "subKem": new_device.kem_pub.hex(),
        "scope": qr_payload_obj["requestedScope"],
        "nbf": nbf,
        "exp": exp,
        "nonce": cert_nonce,
    }
    # Cap-cert domain tag — must equal the protocol's CAP_CERT_DOMAIN (cap.ts /
    # cap.py). The install-side vector test (verify_cap_cert) fails if it drifts.
    cert_canonical = "starfish-capcert-v1\n" + stable_stringify(cert_body)
    cert_sig = ed_sign(alice.ed_priv, cert_canonical.encode("utf-8"))
    assert ed_verify(alice.ed_pub, cert_sig, cert_canonical.encode("utf-8"))
    cap_cert = {**cert_body, "sig": base64.b64encode(cert_sig).decode("ascii")}

    # Step 2b: Wrap the current CEK of each in-scope collection for new_device.kem_pub.
    cek_notes = bytes.fromhex("1111111111111111111111111111111111111111111111111111111111111111")
    cek_tasks = bytes.fromhex("2222222222222222222222222222222222222222222222222222222222222222")

    def _wrap(cek: bytes):
        iv = hkdf(cek + new_device.kem_pub, b"starfish-wrap-iv-vector", b"iv", length=12)
        eph_priv = deterministic_eph_key(cek, new_device.kem_pub)
        ct_b64, eph_pub = wrap_for_recipient(cek, new_device.kem_pub, eph_priv, iv)
        return {"ephKem": eph_pub.hex(), "ct": ct_b64}

    wrapped_ceks = {
        "notes": {"epoch": 1, **_wrap(cek_notes)},
        "tasks": {"epoch": 1, **_wrap(cek_tasks)},
    }

    # Step 3: Bundle. `qrNonce` is echoed from the QR so the new device can
    # bind the bundle to its pairing session (verified via expectedQrNonce).
    bundle = {
        "v": 1,
        "capCert": cap_cert,
        "rootEdPub": alice.ed_pub.hex(),
        "wrappedCEKs": wrapped_ceks,
        "qrNonce": qr_payload_obj["qrNonce"],
    }

    # Step 4: New device unwraps each wrapped CEK and recovers the plaintext.
    for col, expected in (("notes", cek_notes), ("tasks", cek_tasks)):
        entry = wrapped_ceks[col]
        recovered = unwrap_for_recipient(
            entry["ct"], new_device.kem_priv, bytes.fromhex(entry["ephKem"])
        )
        assert recovered == expected, f"unwrap failed for collection {col}"

    out = {
        "description": (
            "Cross-language vector for v3.0 in-person QR pairing. Covers the full "
            "roundtrip: new device QR payload → root device mints cap-cert + wraps "
            "in-scope CEKs → new device installs by verifying the cap-cert and "
            "unwrapping each CEK. Locks both the cap-cert signature and the wrap "
            "format."
        ),
        "root": {"edPub": alice.ed_pub.hex(), "userId": alice.user_id},
        "newDevice": {
            "label": new_device.label,
            "edPub": new_device.ed_pub.hex(),
            "edPriv": new_device.ed_priv.hex(),
            "kemPub": new_device.kem_pub.hex(),
            "kemPriv": new_device.kem_priv.hex(),
        },
        "qrPayload": {
            "object": qr_payload_obj,
            "canonicalUtf8": qr_payload_canonical,
            "base64UrlEncoded": qr_payload_b64url,
        },
        "capCert": {
            "cert": cap_cert,
            "canonicalSigningInput": cert_canonical,
        },
        "ceks": {"notes": cek_notes.hex(), "tasks": cek_tasks.hex()},
        "bundle": bundle,
        "unwrapChecks": [
            {"collection": "notes", "expectedCekHex": cek_notes.hex()},
            {"collection": "tasks", "expectedCekHex": cek_tasks.hex()},
        ],
    }

    out_path = pathlib.Path(__file__).resolve().parents[1] / "pairing-bundle.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
