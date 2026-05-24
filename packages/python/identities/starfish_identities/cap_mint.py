"""Device cap-cert minting helpers (Python mirror of the TS
``identities/cap-mint`` module).

Higher-level convenience over :func:`starfish_protocol.sign_cap_cert`. The
mint helper does the boilerplate (build the unsigned cert, derive
``issUserId`` from the issuer pubkey, fill ``nbf``/``exp``, generate the
nonce, run the well-formedness check, and finally sign).

Member-side helpers (``mint_member_cap`` + ``scopes.read_only``/``writer``/
``admin``) live in ``starfish_sharing.cap_mint``.
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from dataclasses import dataclass
from typing import Any, Optional, TypedDict

from starfish_protocol.cap import (
    CapCert,
    assert_cap_cert_well_formed,
    sign_cap_cert,
)


class ScopePreset(TypedDict, total=False):
    """Operations + paths + collections a minted cap-cert authorizes."""

    ops: list[str]
    collections: list[str]
    paths: list[str]


@dataclass
class MintOpts:
    """Optional knobs for the mint helpers."""

    ttl_sec: Optional[int] = None
    nbf: Optional[int] = None
    nonce: Optional[bytes] = None


class scopes:
    """Built-in scope presets — identities side."""

    @staticmethod
    def root_all() -> ScopePreset:
        """Root-grade access to everything — used for device caps."""
        return {
            "ops": ["read", "list", "write"],
            "paths": ["**"],
            "collections": ["*"],
        }


_DEFAULT_TTL_SEC = 30 * 24 * 3600
_NONCE_LEN = 16


def _user_id_from_pub_hex(pub_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:32]


def _resolve_nbf_exp(opts: Optional[MintOpts]) -> tuple[int, int, bytes]:
    nbf = opts.nbf if opts is not None and opts.nbf is not None else int(time.time())
    ttl = opts.ttl_sec if opts is not None and opts.ttl_sec is not None else _DEFAULT_TTL_SEC
    exp = nbf + ttl
    nonce = opts.nonce if opts is not None and opts.nonce is not None else os.urandom(_NONCE_LEN)
    return nbf, exp, nonce


def mint_device_cap(
    iss_ed_priv_hex: str,
    iss_ed_pub_hex: str,
    sub: dict[str, str],
    scope: ScopePreset | dict[str, Any],
    opts: Optional[MintOpts] = None,
) -> CapCert:
    """Mint a ``device`` cap-cert: the subject acts as a proxy for the issuer.

    ``sub`` must include ``edPubHex`` and ``kemPubHex``.

    Raises :class:`ValueError` (with the well-formedness code as
    ``args[0]``) on malformed input.
    """
    nbf, exp, nonce_bytes = _resolve_nbf_exp(opts)
    unsigned: dict[str, Any] = {
        "v": 1,
        "kind": "device",
        "iss": iss_ed_pub_hex,
        "issUserId": _user_id_from_pub_hex(iss_ed_pub_hex),
        "sub": sub["edPubHex"],
        "subKem": sub["kemPubHex"],
        "scope": dict(scope),
        "nbf": nbf,
        "exp": exp,
        "nonce": base64.b64encode(nonce_bytes).decode("ascii"),
    }
    assert_cap_cert_well_formed(unsigned)
    return sign_cap_cert(unsigned, iss_ed_priv_hex)  # type: ignore[return-value]


__all__ = [
    "MintOpts",
    "ScopePreset",
    "mint_device_cap",
    "scopes",
]
