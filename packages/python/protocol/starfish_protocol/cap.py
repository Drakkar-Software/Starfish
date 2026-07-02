"""Capability certificate (cap-cert) types and canonical encoding.

v3.0 capability-based access control: the cap-cert is the bearer of
authority. Root principals sign one per device (proxy) or per member
(scoped grant). This module exports the canonical signing-input helper
plus signing and verification primitives.

Starfish speaks a single signature suite on the wire (Ed25519 signing +
X25519 KEM). External roots (e.g. secp256k1/Nostr) bootstrap into a
Starfish identity via a derivation in ``starfish_identities``; the
resulting identity is a normal Ed25519 identity from the wire's
perspective.
"""

import base64
import binascii
import hashlib
import math
import re
from typing import Any, Literal, TypedDict

try:
    from typing import NotRequired
except ImportError:  # pragma: no cover - safety net for older runtimes
    from typing_extensions import NotRequired  # type: ignore[assignment]

from starfish_protocol.hash import stable_stringify
from starfish_protocol.suites import ed25519 as ed25519_suite


CapKind = Literal["device", "member", "audience"]


class CapScope(TypedDict):
    """Operations and resources a cap-cert authorizes.

    `paths` entries are glob-style; entries prefixed with ``!`` are denylist
    rules (explicit deny beats wildcard allow). `paths` is optional.
    """

    ops: list[Literal["read", "write", "list"]]
    collections: list[str]
    paths: NotRequired[list[str]]


class CapCert(TypedDict):
    """Capability certificate (signed).

    ``kind: "device"`` / ``"member"`` bind a single subject: ``sub`` (Ed25519
    signing pubkey) and ``subKem`` (X25519 KEM pubkey) are present.
    ``subUserId`` is mandatory for ``member``, optional for ``device``.
    ``kind: "audience"`` binds **no** subject: ``sub``, ``subKem``, and
    ``subUserId`` are **absent** and the optional ``aud`` allow-list is
    present instead.
    """

    v: Literal[1]
    kind: CapKind
    # Issuer Ed25519 pubkey, hex (32 B).
    iss: str
    # sha256(iss)[0:32].
    issUserId: str
    # Subject Ed25519 signing pubkey, hex (32 B). Absent for audience.
    sub: NotRequired[str]
    # Subject X25519 KEM pubkey, hex (32 B). Absent for audience.
    subKem: NotRequired[str]
    # sha256(sub)[0:32]; required for member caps, optional for device caps,
    # absent for audience caps.
    subUserId: NotRequired[str]
    scope: CapScope
    # Allow-list of subject Ed25519 pubkeys (64-char lowercase hex) for audience
    # caps. When present it MUST be non-empty; absent ⇒ any identity may redeem.
    aud: NotRequired[list[str]]
    nbf: int
    exp: int
    nonce: str
    sig: str


_CAP_CERT_DOMAIN = "starfish-capcert-v1\n"


def cap_cert_canonical_signing_input(cert: dict[str, Any]) -> str:
    """Return the canonical UTF-8 string used as the Ed25519 signing input."""
    unsigned = {k: v for k, v in cert.items() if k != "sig"}
    return _CAP_CERT_DOMAIN + stable_stringify(unsigned)


def _user_id_from_pub_hex(pub_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:32]


def user_id_from_pub_hex(pub_hex: str) -> str:
    """Derive a userId from an Ed25519 public key: ``sha256(hexDecode(pub_hex))[0:32]``."""
    return _user_id_from_pub_hex(pub_hex)


def recipient_kem(cert: dict[str, Any]) -> str:
    """Resolve a subject cap-cert's KEM recipient pubkey (X25519, hex).

    Returns ``cert["subKem"]`` (the dedicated X25519 KEM key) when present,
    falling back to ``cert["sub"]``. Raises ``ValueError`` for a subject-less
    (audience) cap.
    """
    kem_pub_hex = cert.get("subKem")
    if kem_pub_hex is None:
        kem_pub_hex = cert.get("sub")
    if kem_pub_hex is None:
        raise ValueError("recipient_kem: cap binds no subject KEM key (audience cap?)")
    return kem_pub_hex


def path_glob_match(glob: str, target: str) -> bool:
    """Glob match used for cap-cert path semantics. See the TS ``pathGlobMatch``
    helper for the rules. Mirrored byte-for-byte.

    Linear two-pointer matcher. Compiling an attacker-controlled glob to a regex
    (``*`` -> ``[^/]*``, ``**`` -> ``.*``) backtracks super-polynomially on a
    crafted non-match, and this runs on the auth hot path for every request, so
    it is a ReDoS sink. This is O(len(glob) * len(target)) with no backtracking
    explosion. ``**`` matches any run of characters (incl. ``/`` and line
    terminators); ``*`` matches any run of non-``/`` characters."""
    # Tokens: 2 = ``**``, 1 = ``*``, otherwise a literal character.
    toks: list[tuple[int, str]] = []
    i = 0
    n = len(glob)
    while i < n:
        ch = glob[i]
        if ch == "*" and i + 1 < n and glob[i + 1] == "*":
            toks.append((2, ""))
            i += 2
        elif ch == "*":
            toks.append((1, ""))
            i += 1
        else:
            toks.append((0, ch))
            i += 1

    si = 0  # index into target
    ti = 0  # index into toks
    star_ti = -1  # token index of the most recent star we can backtrack to
    star_type = 1
    star_match = 0  # target index the star began matching at
    n_toks = len(toks)
    n_target = len(target)
    while si < n_target:
        if ti < n_toks and toks[ti][0] == 0 and toks[ti][1] == target[si]:
            si += 1
            ti += 1
        elif ti < n_toks and toks[ti][0] != 0:
            star_ti = ti
            star_type = toks[ti][0]
            star_match = si
            ti += 1
        elif star_ti != -1:
            # Extend the previous star by one target character. A single ``*``
            # may not absorb a ``/``; ``**`` absorbs anything.
            if star_type == 1 and target[star_match] == "/":
                return False
            star_match += 1
            si = star_match
            ti = star_ti + 1
        else:
            return False
    while ti < n_toks and toks[ti][0] != 0:
        ti += 1
    return ti == n_toks


def is_root_device_cap(cert: dict[str, Any]) -> bool:
    """True when ``cert`` is a self-signed device cap (issuer is its own subject)."""
    return cert.get("kind") == "device" and cert.get("iss") == cert.get("sub")


CapCertWellFormedCode = Literal[
    "malformed-shape",
    "iss-userid-mismatch",
    "sub-userid-mismatch",
    "member-missing-sub-userid",
    "member-self",
    "member-wildcard-collections",
    "member-multi-collection",
    "member-private-path",
    "member-members-not-denied",
    "member-keyring-not-denied",
    "audience-has-sub",
    "non-audience-has-aud",
    "audience-empty-aud",
    "audience-aud-too-large",
    "audience-aud-bad-entry",
    "audience-aud-dup",
]

_VALID_OPS = frozenset(("read", "write", "list"))
_NONCE_LEN_BYTES = 16
_MAX_AUDIENCE = 64
_AUD_ENTRY_RE = re.compile(r"[0-9a-f]{64}")


def _is_js_integer(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    if isinstance(value, float):
        return math.isfinite(value) and value.is_integer()
    return False


class CapCertVerifyResult(TypedDict, total=False):
    ok: bool
    reason: str


class UnsignedCapCert(TypedDict):
    """Cap-cert without its signature — the value whose canonical
    stable-stringification is the Ed25519 signing input."""

    v: Literal[1]
    kind: CapKind
    iss: str
    issUserId: str
    sub: NotRequired[str]
    subKem: NotRequired[str]
    subUserId: NotRequired[str]
    scope: CapScope
    aud: NotRequired[list[str]]
    nbf: int
    exp: int
    nonce: str


def assert_cap_cert_well_formed(cert: dict[str, Any]) -> None:
    """Generic, kind-agnostic cap-cert structural checks.

    Raises ``ValueError`` whose ``args[0]`` is one of the codes in
    ``CapCertWellFormedCode``.
    """
    if cert.get("kind") not in ("device", "member", "audience"):
        raise ValueError("malformed-shape")
    is_audience = cert.get("kind") == "audience"
    for key in ("iss", "issUserId", "nonce"):
        if not isinstance(cert.get(key), str):
            raise ValueError("malformed-shape")
    if is_audience:
        if "sub" in cert or "subKem" in cert or "subUserId" in cert:
            raise ValueError("audience-has-sub")
    else:
        if not isinstance(cert.get("sub"), str):
            raise ValueError("malformed-shape")
        if not isinstance(cert.get("subKem"), str):
            raise ValueError("malformed-shape")
    if not _is_js_integer(cert.get("nbf")) or not _is_js_integer(cert.get("exp")):
        raise ValueError("malformed-shape")
    try:
        nonce_bytes = base64.b64decode(cert["nonce"], validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("malformed-shape")
    if len(nonce_bytes) != _NONCE_LEN_BYTES:
        raise ValueError("malformed-shape")
    if "subUserId" in cert and not isinstance(cert["subUserId"], str):
        raise ValueError("malformed-shape")
    sub_user_id = cert.get("subUserId")
    scope = cert.get("scope")
    if not isinstance(scope, dict):
        raise ValueError("malformed-shape")
    ops = scope.get("ops")
    if not isinstance(ops, list) or any(o not in _VALID_OPS for o in ops):
        raise ValueError("malformed-shape")
    collections = scope.get("collections")
    if not isinstance(collections, list) or any(not isinstance(c, str) for c in collections):
        raise ValueError("malformed-shape")
    paths = scope.get("paths")
    if paths is not None and (
        not isinstance(paths, list) or any(not isinstance(p, str) for p in paths)
    ):
        raise ValueError("malformed-shape")

    if is_audience:
        if "aud" in cert:
            _assert_aud_list(cert["aud"])
    elif "aud" in cert:
        raise ValueError("non-audience-has-aud")

    iss = cert["iss"]
    iss_user_id = cert["issUserId"]
    if _user_id_from_pub_hex(iss) != iss_user_id:
        raise ValueError("iss-userid-mismatch")

    if sub_user_id is not None:
        if _user_id_from_pub_hex(cert["sub"]) != sub_user_id:
            raise ValueError("sub-userid-mismatch")


def _assert_aud_list(aud: Any) -> None:
    if not isinstance(aud, list):
        raise ValueError("audience-aud-bad-entry")
    if len(aud) == 0:
        raise ValueError("audience-empty-aud")
    if len(aud) > _MAX_AUDIENCE:
        raise ValueError("audience-aud-too-large")
    for entry in aud:
        if not isinstance(entry, str) or _AUD_ENTRY_RE.fullmatch(entry) is None:
            raise ValueError("audience-aud-bad-entry")
    if len(set(aud)) != len(aud):
        raise ValueError("audience-aud-dup")


def sign_cap_cert(cert: dict[str, Any], iss_priv_hex: str) -> dict[str, Any]:
    """Sign an unsigned cap-cert with the issuer's Ed25519 private key.

    Returns a new dict identical to ``cert`` with a base64-encoded (standard,
    padded) ``sig`` field added.
    """
    unsigned = {k: v for k, v in cert.items() if k != "sig"}
    message = cap_cert_canonical_signing_input(unsigned).encode("utf-8")
    sig_bytes = ed25519_suite.sign(message, iss_priv_hex)
    return {**unsigned, "sig": base64.b64encode(sig_bytes).decode("ascii")}


def verify_cap_cert_signature(cert: dict[str, Any]) -> bool:
    """Return ``True`` iff ``cert["sig"]`` verifies against ``cert["iss"]``."""
    try:
        message = cap_cert_canonical_signing_input(cert).encode("utf-8")
        sig_bytes = base64.b64decode(cert["sig"])
        return ed25519_suite.verify(sig_bytes, message, cert["iss"])
    except Exception:
        return False


def verify_cap_cert(
    cert: dict[str, Any],
    *,
    now: int,
    clock_skew_sec: int = 300,
) -> dict[str, Any]:
    """Orchestrated verification: time window + well-formedness + signature."""
    try:
        assert_cap_cert_well_formed(cert)
    except ValueError as e:
        return {"ok": False, "reason": e.args[0] if e.args else "malformed"}
    if cert["exp"] <= cert["nbf"]:
        return {"ok": False, "reason": "inverted-window"}
    if now < cert["nbf"] - clock_skew_sec:
        return {"ok": False, "reason": "not-yet-valid"}
    if now > cert["exp"] + clock_skew_sec:
        return {"ok": False, "reason": "expired"}
    if not verify_cap_cert_signature(cert):
        return {"ok": False, "reason": "bad-signature"}
    return {"ok": True}
