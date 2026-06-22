"""Generate tests/test-vectors/spaces-kemsig.json.

Generates fixed sign_kem_sig / verify_kem_sig test cases using fixture Ed25519
keys from _common.py.  The signatures are deterministic since Ed25519 is
deterministic (no random nonce).

Usage::

    uv run --python 3.12 python tests/test-vectors/_generators/spaces_kemsig.py

from the repo root.
"""

from __future__ import annotations

import json
import pathlib
import sys

_REPO_ROOT = pathlib.Path(__file__).parents[3]
_GENERATORS = pathlib.Path(__file__).parent
for p in [str(_REPO_ROOT), str(_GENERATORS)]:
    if p not in sys.path:
        sys.path.insert(0, p)

_SPACES_PKG = _REPO_ROOT / "packages" / "python" / "spaces"
if str(_SPACES_PKG) not in sys.path:
    sys.path.insert(0, str(_SPACES_PKG))

from _common import load_fixture  # noqa: E402
from starfish_spaces.request_verify import sign_kem_sig, verify_kem_sig  # noqa: E402

alice = load_fixture("alice_dev_1")
bob = load_fixture("bob_dev_1")

# Helper: bytes → hex via Identity.to_dict() or .hex()
a_ed_priv = alice.ed_priv.hex()
a_ed_pub = alice.ed_pub.hex()
a_kem_pub = alice.kem_pub.hex()
b_ed_pub = bob.ed_pub.hex()
b_ed_priv = bob.ed_priv.hex()
b_kem_pub = bob.kem_pub.hex()

# ── sign cases ────────────────────────────────────────────────────────────────

sign_cases = [
    {
        "label": "alice-device-kem-sig",
        "edPriv": a_ed_priv,
        "kemPub": a_kem_pub,
        "sig": sign_kem_sig(a_kem_pub, a_ed_priv),
    },
    {
        "label": "bob-device-kem-sig",
        "edPriv": b_ed_priv,
        "kemPub": b_kem_pub,
        "sig": sign_kem_sig(b_kem_pub, b_ed_priv),
    },
]

# ── verify cases ──────────────────────────────────────────────────────────────

verify_cases = [
    {
        "label": "valid-alice",
        "edPub": a_ed_pub,
        "kemPub": a_kem_pub,
        "sig": sign_kem_sig(a_kem_pub, a_ed_priv),
        "expected": True,
    },
    {
        "label": "wrong-key-alice",
        "edPub": a_ed_pub,
        "kemPub": b_kem_pub,  # wrong kemPub
        "sig": sign_kem_sig(a_kem_pub, a_ed_priv),  # signed over alice's KEM key
        "expected": False,
    },
    {
        "label": "wrong-signer",
        "edPub": b_ed_pub,   # bob's pubkey
        "kemPub": a_kem_pub,
        "sig": sign_kem_sig(a_kem_pub, a_ed_priv),  # signed by alice
        "expected": False,
    },
    {
        "label": "empty-sig",
        "edPub": a_ed_pub,
        "kemPub": a_kem_pub,
        "sig": "",
        "expected": False,
    },
]

out = {"sign": sign_cases, "verify": verify_cases}
OUTPUT = _REPO_ROOT / "tests" / "test-vectors" / "spaces-kemsig.json"
OUTPUT.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
print(f"wrote {OUTPUT}")
