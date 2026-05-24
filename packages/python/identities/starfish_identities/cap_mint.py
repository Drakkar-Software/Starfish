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
from starfish_protocol.suites import Alg, DEFAULT_ALG, suite_has_separate_kem


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
    # Issuer's crypto suite (governs the cap signature). Defaults to system default.
    alg: Alg = DEFAULT_ALG
    # Subject's signing suite (governs sub + per-request sigs). Defaults to ``alg``.
    sub_alg: Optional[Alg] = None
    # Subject's KEM suite (governs subKem). Defaults to ``sub_alg``.
    sub_kem_alg: Optional[Alg] = None


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
    iss_alg: Alg = opts.alg if opts is not None else DEFAULT_ALG
    sub_alg: Alg = (opts.sub_alg if opts is not None and opts.sub_alg is not None else iss_alg)
    sub_kem_alg: Alg = (
        opts.sub_kem_alg if opts is not None and opts.sub_kem_alg is not None else sub_alg
    )
    # subKem is omitted only when the KEM key IS the signing key (same-suite
    # single-key suite); otherwise it carries a distinct KEM pubkey of suite
    # `sub_kem_alg`. The keyring now wraps under any suite's ECDH
    # (``recipient_kem``), so every ``sub_kem_alg`` is mintable.
    kem_key_is_sign_key = sub_kem_alg == sub_alg and not suite_has_separate_kem(sub_kem_alg)
    unsigned: dict[str, Any] = {
        "v": 1,
        "kind": "device",
        "issAlg": iss_alg,
        "subAlg": sub_alg,
        "iss": iss_ed_pub_hex,
        "issUserId": _user_id_from_pub_hex(iss_ed_pub_hex),
        "sub": sub["edPubHex"],
        "scope": dict(scope),
        "nbf": nbf,
        "exp": exp,
        "nonce": base64.b64encode(nonce_bytes).decode("ascii"),
    }
    if sub_kem_alg != sub_alg:
        unsigned["subKemAlg"] = sub_kem_alg
    if not kem_key_is_sign_key:
        unsigned["subKem"] = sub["kemPubHex"]
    assert_cap_cert_well_formed(unsigned)
    return sign_cap_cert(unsigned, iss_ed_priv_hex)  # type: ignore[return-value]


__all__ = [
    "MintOpts",
    "ScopePreset",
    "mint_device_cap",
    "scopes",
]
