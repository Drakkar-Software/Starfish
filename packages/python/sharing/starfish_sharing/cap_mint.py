"""Member cap-cert minting + member-side scope presets (Python mirror of
TS ``sharing/cap-mint.ts``).

Member presets encode owner-only deny rules for the per-collection
``_members`` (and, for the writer preset, ``_keyring``) paths so the
minted cert is well-formed against the protocol's
``assert_cap_cert_well_formed`` member-rule block.
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
    path_glob_match,
    sign_cap_cert,
)


class ScopePreset(TypedDict, total=False):
    """Operations + paths + collections a minted cap-cert authorizes."""

    ops: list[str]
    collections: list[str]
    paths: list[str]


@dataclass
class MintOpts:
    """Optional knobs for the mint helper.

    ``expires_at`` (absolute unix seconds), when set, wins over ``ttl_sec`` and
    maps directly to the cap's ``exp``; it must be strictly after ``nbf``.
    """

    ttl_sec: Optional[int] = None
    expires_at: Optional[int] = None
    nbf: Optional[int] = None
    nonce: Optional[bytes] = None


@dataclass
class AudienceMintOpts(MintOpts):
    """Optional knobs for :func:`mint_audience_cap`.

    ``audience`` is an allow-list of redeemer Ed25519 pubkeys (64-char lowercase
    hex); when provided (non-empty) only those identities may redeem, and its
    absence means any identity may. Maps to the cap's ``aud``.
    """

    audience: Optional[list[str]] = None


class scopes:
    """Built-in scope presets.

    The member presets (``read_only``, ``writer``) deny ``<col>/_keyring`` and
    ``<col>/_members`` because those are owner-only — a member cap that could
    reach them is rejected at mint and at server validation time. ``admin``
    carries no such deny, so it is valid only for a **device** cap
    (``mint_device_cap``); passing it to ``mint_member_cap`` is rejected.
    """

    @staticmethod
    def read_only(c: str) -> ScopePreset:
        """Read-only access to a single collection (including nested paths)."""
        return {
            "ops": ["read", "list"],
            "paths": [f"{c}/**", f"!{c}/_members"],
            "collections": [c],
        }

    @staticmethod
    def writer(c: str) -> ScopePreset:
        """Read + list + write, denying ``_keyring`` and ``_members``."""
        return {
            "ops": ["read", "list", "write"],
            "paths": [f"{c}/**", f"!{c}/_keyring", f"!{c}/_members"],
            "collections": [c],
        }

    @staticmethod
    def admin(c: str) -> ScopePreset:
        """Full read+list+write — manages the keyring and member directory.

        Valid only for a **device** cap (``mint_device_cap``);
        ``mint_member_cap`` rejects it because a member cap must never reach
        ``<col>/_keyring`` or ``<col>/_members``.
        """
        return {
            "ops": ["read", "list", "write"],
            "paths": [f"{c}/**"],
            "collections": [c],
        }


_DEFAULT_TTL_SEC = 30 * 24 * 3600
_NONCE_LEN = 16


def _user_id_from_pub_hex(pub_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:32]


def _resolve_nbf_exp(opts: Optional[MintOpts]) -> tuple[int, int, bytes]:
    """Resolve ``nbf``/``exp``/nonce from the mint opts.

    ``expires_at`` wins over ``ttl_sec``; otherwise ``exp = nbf + ttl``. An
    ``expires_at`` that is not strictly after ``nbf`` is rejected so the cap
    never carries an inverted validity window. Identical rule to the TS
    ``resolveValidity``.
    """
    nbf = opts.nbf if opts is not None and opts.nbf is not None else int(time.time())
    expires_at = opts.expires_at if opts is not None else None
    if expires_at is not None:
        if expires_at <= nbf:
            raise ValueError("expiresAt-not-after-nbf")
        exp = expires_at
    else:
        ttl = opts.ttl_sec if opts is not None and opts.ttl_sec is not None else _DEFAULT_TTL_SEC
        exp = nbf + ttl
    nonce = opts.nonce if opts is not None and opts.nonce is not None else os.urandom(_NONCE_LEN)
    return nbf, exp, nonce


def mint_member_cap(
    iss_ed_priv_hex: str,
    iss_ed_pub_hex: str,
    sub: dict[str, str],
    collection: str,
    scope: ScopePreset | dict[str, Any],
    opts: Optional[MintOpts] = None,
) -> CapCert:
    """Mint a ``member`` cap-cert: the subject keeps their own identity.

    ``sub`` must include ``edPubHex``, ``kemPubHex``, and ``userIdHex``.

    ``collection`` is the single collection name this cap grants access to;
    it is forced into ``scope.collections`` (overriding any value the caller
    may have passed in ``scope``).

    Raises :class:`ValueError` with one of the codes ``"member-self"``,
    ``"member-wildcard-collections"``, ``"member-multi-collection"``,
    ``"member-private-path"``, ``"member-members-not-denied"``, or
    ``"member-keyring-not-denied"`` when the input is malformed.
    """
    nbf, exp, nonce_bytes = _resolve_nbf_exp(opts)
    scope_dict: dict[str, Any] = dict(scope)
    scope_dict["collections"] = [collection]
    unsigned: dict[str, Any] = {
        "v": 1,
        "kind": "member",
        "iss": iss_ed_pub_hex,
        "issUserId": _user_id_from_pub_hex(iss_ed_pub_hex),
        "sub": sub["edPubHex"],
        "subKem": sub["kemPubHex"],
        "subUserId": sub["userIdHex"],
        "scope": scope_dict,
        "nbf": nbf,
        "exp": exp,
        "nonce": base64.b64encode(nonce_bytes).decode("ascii"),
    }
    assert_member_cap_shape(unsigned)
    return sign_cap_cert(unsigned, iss_ed_priv_hex)  # type: ignore[return-value]


def assert_member_cap_shape(cert: dict[str, Any] | CapCert) -> None:
    """Assert the structural shape of a ``member`` cap-cert.

    Authoritative owner of the member-cap rules — ``starfish_protocol`` only
    checks the generic iss/sub-userId relations; the member-specific barriers
    live here. Used by :func:`mint_member_cap` (mint guard) and by
    ``sharing_server_plugin`` (server-side validation under the resolver's
    plugin dispatch).

    Raises ``ValueError`` whose ``args[0]`` is one of ``"member-self"``,
    ``"member-wildcard-collections"``, ``"member-multi-collection"``,
    ``"member-private-path"``, ``"member-members-not-denied"``,
    ``"member-keyring-not-denied"``, or ``"member-missing-sub-userid"``.
    Non-member caps pass through after the generic protocol checks.
    """
    assert_cap_cert_well_formed(cert)
    if cert.get("kind") != "member":
        return

    iss_user_id = cert["issUserId"]
    sub_user_id = cert.get("subUserId")
    if sub_user_id is None:
        raise ValueError("member-missing-sub-userid")
    if sub_user_id == iss_user_id:
        raise ValueError("member-self")
    if "*" in cert["scope"]["collections"]:
        raise ValueError("member-wildcard-collections")
    if len(cert["scope"]["collections"]) != 1:
        raise ValueError("member-multi-collection")
    _assert_scope_barriers(
        cert,
        private_path="member-private-path",
        members_not_denied="member-members-not-denied",
        keyring_not_denied="member-keyring-not-denied",
    )


def _assert_scope_barriers(
    cert: dict[str, Any] | CapCert,
    *,
    private_path: str,
    members_not_denied: str,
    keyring_not_denied: str,
) -> None:
    """Owner-namespace scope barriers shared by every subject-scoped cap kind
    (``member`` + ``audience``). One source of truth for these security-critical
    checks; the caller supplies the raised codes so each kind surfaces its own
    reason over identical logic:

    - no scope path may resolve into the issuer's ``users/<issUserId>/`` namespace;
    - any allow rule that matches ``<col>/_members`` requires a sibling deny;
    - any **write** allow rule matching ``<col>/_keyring`` requires a sibling deny.

    ``{identity}`` resolves to ``iss_user_id`` here (mint-time) — strictly more
    restrictive than the resolver's subject substitution, so it can never create
    a request-time escalation. Glob matching delegates to ``path_glob_match`` so
    mint barriers and request-path enforcement never drift.
    """
    iss_user_id = cert["issUserId"]
    issuer_ns_exact = f"users/{iss_user_id}"
    issuer_ns_prefix = f"users/{iss_user_id}/"
    scope_paths: list[str] = list(cert["scope"].get("paths", []) or [])
    # A cap with NO ``scope.paths`` (or an empty list) is path-UNRESTRICTED:
    # ``match_scope_path(_, None)`` returns True at request time, so it
    # effectively allows every path with no deny — including the owner-only
    # ``_members``/``_keyring``. Model that as an implicit ``**`` allow so the
    # barriers below fire (a subject-scoped member/audience cap must carry an
    # explicit path scope that denies those paths; only a device/root cap, which
    # does not go through these barriers, may be path-unrestricted).
    path_unrestricted = len(scope_paths) == 0
    for path in scope_paths:
        resolved = path.replace("{identity}", iss_user_id)
        if resolved == issuer_ns_exact or resolved.startswith(issuer_ns_prefix):
            raise ValueError(private_path)
    resolved_allows: list[tuple[str, str]] = []
    resolved_denies: list[str] = []
    for entry in scope_paths:
        if entry.startswith("!"):
            resolved_denies.append(entry[1:].replace("{identity}", iss_user_id))
        else:
            resolved_allows.append((entry, entry.replace("{identity}", iss_user_id)))
    for col in cert["scope"]["collections"]:
        members_path = f"{col}/_members"
        matching_allow = (
            ("**", "**")
            if path_unrestricted
            else next(
                (a for a in resolved_allows if path_glob_match(a[1], members_path)),
                None,
            )
        )
        if matching_allow is None:
            continue
        if path_unrestricted or not any(
            path_glob_match(d, members_path) for d in resolved_denies
        ):
            raise ValueError(members_not_denied)
    if "write" in cert["scope"]["ops"]:
        for col in cert["scope"]["collections"]:
            keyring_path = f"{col}/_keyring"
            matching_allow = (
                ("**", "**")
                if path_unrestricted
                else next(
                    (a for a in resolved_allows if path_glob_match(a[1], keyring_path)),
                    None,
                )
            )
            if matching_allow is None:
                continue
            if path_unrestricted or not any(
                path_glob_match(d, keyring_path) for d in resolved_denies
            ):
                raise ValueError(keyring_not_denied)


def mint_audience_cap(
    iss_ed_priv_hex: str,
    iss_ed_pub_hex: str,
    collection: str,
    scope: ScopePreset | dict[str, Any],
    opts: Optional[AudienceMintOpts] = None,
) -> CapCert:
    """Mint an ``audience`` cap-cert: a public-link credential binding **no**
    single subject.

    Each redeemer signs requests with their own key (named via the
    ``X-Starfish-Pub`` header); an optional ``opts.audience`` allow-list
    restricts who may redeem, and its absence means any identity may. Carries no
    ``sub``/``subKem``/``subUserId`` — those keys are deliberately omitted so the
    canonical signing input stays deterministic across languages.

    ``collection`` is forced into ``scope.collections`` (single-collection by
    design). Raises :class:`ValueError` with an ``audience-*`` code on a
    malformed scope or ``aud``.
    """
    nbf, exp, nonce_bytes = _resolve_nbf_exp(opts)
    scope_dict: dict[str, Any] = dict(scope)
    scope_dict["collections"] = [collection]
    unsigned: dict[str, Any] = {
        "v": 1,
        "kind": "audience",
        "iss": iss_ed_pub_hex,
        "issUserId": _user_id_from_pub_hex(iss_ed_pub_hex),
        "scope": scope_dict,
        "nbf": nbf,
        "exp": exp,
        "nonce": base64.b64encode(nonce_bytes).decode("ascii"),
    }
    audience = opts.audience if opts is not None else None
    if audience is not None:
        # An explicitly-empty list almost certainly means "restrict to nobody" by
        # mistake; silently dropping it would mint an OPEN link (any identity).
        # Reject it — callers who want an open link omit ``audience`` entirely.
        if len(audience) == 0:
            raise ValueError("audience-empty")
        unsigned["aud"] = audience
    assert_audience_cap_shape(unsigned)
    return sign_cap_cert(unsigned, iss_ed_priv_hex)  # type: ignore[return-value]


def assert_audience_cap_shape(cert: dict[str, Any] | CapCert) -> None:
    """Assert the structural shape of an ``audience`` cap-cert.

    Mirrors :func:`assert_member_cap_shape` minus the single-subject rules (an
    audience cap has no ``sub``/``subUserId``); keeps the single-collection and
    owner-namespace barriers via :func:`_assert_scope_barriers`. Used by
    :func:`mint_audience_cap` (mint guard) and ``sharing_server_plugin``
    (server-side validation). Raises :class:`ValueError` whose ``args[0]`` is one
    of ``"audience-wildcard-collections"``, ``"audience-multi-collection"``,
    ``"audience-private-path"``, ``"audience-members-not-denied"``,
    ``"audience-keyring-not-denied"``. Non-audience caps pass through after the
    generic protocol checks.
    """
    assert_cap_cert_well_formed(cert)
    if cert.get("kind") != "audience":
        return
    if "*" in cert["scope"]["collections"]:
        raise ValueError("audience-wildcard-collections")
    if len(cert["scope"]["collections"]) != 1:
        raise ValueError("audience-multi-collection")
    _assert_scope_barriers(
        cert,
        private_path="audience-private-path",
        members_not_denied="audience-members-not-denied",
        keyring_not_denied="audience-keyring-not-denied",
    )


__all__ = [
    "MintOpts",
    "AudienceMintOpts",
    "ScopePreset",
    "mint_member_cap",
    "mint_audience_cap",
    "scopes",
    "assert_member_cap_shape",
    "assert_audience_cap_shape",
]
