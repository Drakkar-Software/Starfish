"""Generate tests/test-vectors/spaces-userid.json.

Generates ``default_user_id_from_ed_pub`` for several fixed ed public keys.
Deterministic: sha256(bytes.fromhex(edPub))[:16].hex().

Usage::

    uv run --python 3.12 python tests/test-vectors/_generators/spaces_userid.py

from the repo root.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import pathlib
import sys

_REPO_ROOT = pathlib.Path(__file__).parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_SPACES_PKG = _REPO_ROOT / "packages" / "python" / "spaces"
if str(_SPACES_PKG) not in sys.path:
    sys.path.insert(0, str(_SPACES_PKG))

from starfish_spaces.layout import default_user_id_from_ed_pub  # noqa: E402

ED_PUBS = [
    "00" * 32,                         # all-zero key
    "ff" * 32,                         # all-ff key
    "a1b2c3d4" * 8,                    # repeating pattern
    "0123456789abcdef" * 4,            # incrementing nibbles
]


async def _run():
    cases = []
    for ed_pub in ED_PUBS:
        user_id = await default_user_id_from_ed_pub(ed_pub)
        # Cross-check inline
        expected = hashlib.sha256(bytes.fromhex(ed_pub)).digest()[:16].hex()
        assert user_id == expected, f"mismatch: {user_id} != {expected}"
        cases.append({"edPub": ed_pub, "userId": user_id})

    out = {"cases": cases}
    OUTPUT = _REPO_ROOT / "tests" / "test-vectors" / "spaces-userid.json"
    OUTPUT.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {OUTPUT}")


asyncio.run(_run())
