"""Cross-language conformance for the HKDF ``derive_key`` primitive.

Anchors the exact derived-key bytes against the shared test vector so the
TypeScript ``deriveKey`` and Python ``derive_key`` stay byte-for-byte
compatible. (The TS side cannot assert the hex — its derived key is a
non-extractable ``CryptoKey`` — so it round-trips instead.)
"""

import json
import pathlib

from starfish_protocol.crypto import derive_key

VECTORS_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent
    / "tests"
    / "test-vectors"
    / "crypto.json"
)
VECTORS = json.loads(VECTORS_PATH.read_text())


def test_derive_key_matches_vector():
    derived = derive_key(
        VECTORS["secret"], VECTORS["salt"], VECTORS["info"].encode("utf-8")
    )
    assert derived.hex() == VECTORS["derived_key_hex"]
