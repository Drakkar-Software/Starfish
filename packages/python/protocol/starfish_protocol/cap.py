"""Capability certificate (cap-cert) types and canonical encoding.

v3.0 capability-based access control: the cap-cert is the bearer of
authority. Root principals sign one per device (proxy) or per member
(scoped grant). This module exports the canonical signing-input helper
plus signing and verification primitives.
"""

import base64
import binascii
import hashlib
import math
import re
from typing import Any, Literal, TypedDict

try:
    # NotRequired lives in typing on 3.11+, but be defensive.
    from typing import NotRequired
except ImportError:  # pragma: no cover - safety net for older runtimes
    from typing_extensions import NotRequired  # type: ignore[assignment]

from starfish_protocol.hash import stable_stringify
from starfish_protocol.suites import Alg, get_suite, is_alg, suite_has_separate_kem


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

    ``kind: "device"`` / ``"member"`` bind a single subject: ``sub`` and
    ``subKem`` are present (``subUserId`` mandatory for ``member``, optional for
    ``device``). ``kind: "audience"`` binds **no** subject: ``sub``, ``subKem``,
    and ``subUserId`` are **absent** and the optional ``aud`` allow-list is
    present instead. The absence is load-bearing — the canonical signing input
    is a key-sorted stringify, so a stray ``sub``/``subKem`` key would change the
    signed bytes and break cross-language verification.
    """

    v: Literal[1]
    kind: CapKind
    # Issuer's crypto suite — governs how ``sig`` is verified against ``iss``.
    # Part of the canonical signing input (downgrade guard).
    issAlg: Alg
    # Subject's signing suite — governs ``sub`` key type + the subject's
    # per-request signature scheme. Present for device/member, absent for
    # audience. May differ from ``issAlg`` (cross-suite delegation). Absent ⇒
    # same as ``issAlg``.
    subAlg: NotRequired[Alg]
    # Subject's KEM (encryption) suite, decoupled from the signing suite so a
    # subject can sign with one curve and receive encrypted keys under another
    # (e.g. secp256k1 signing + X25519 KEM, or a future PQ KEM). Absent ⇒ same as
    # ``subAlg``. Governs ``subKem``'s key type. Reserved for the keyring KEM
    # phase; omitted today (KEM == signing suite).
    subKemAlg: NotRequired[Alg]
    # Issuer pubkey, hex (32 B) — Ed25519 or secp256k1 x-only per ``issAlg``.
    iss: str
    # sha256(iss)[0:32].
    issUserId: str
    # Subject signing pubkey, hex (32 B) — type per ``subAlg``. Absent for audience.
    sub: NotRequired[str]
    # Subject KEM pubkey, hex (32 B). Present only when ``subAlg`` uses a
    # separate KEM key (ed25519 -> X25519); absent when it derives from ``sub``
    # (secp256k1) and for audience caps.
    subKem: NotRequired[str]
    # sha256(sub)[0:32]; required for member caps, optional for device caps,
    # absent for audience caps.
    subUserId: NotRequired[str]
    scope: CapScope
    # Allow-list of subject Ed25519 pubkeys (64-char lowercase hex) for audience
    # caps. When present it MUST be non-empty; absent ⇒ any identity may redeem.
    # Forbidden on device/member caps.
    #
    # Allow-listed audiences are ed25519-only (enforced): entries are bare
    # 32-byte hex with no suite tag, so the server pins the presenter suite to
    # ed25519 whenever ``aud`` is present — a presenter declaring any other suite
    # is rejected 401. An OPEN audience (no ``aud``) accepts any registered suite.
    aud: NotRequired[list[str]]
    # Not-before, unix seconds.
    nbf: int
    # Expiry, unix seconds.
    exp: int
    # Random nonce, base64-encoded (16 B).
    nonce: str
    # Signature over the canonical signing input under issAlg, base64-encoded.
    sig: str


# Domain-separation tag prepended to a cap-cert signing input. Binds the
# signature to the "cap-cert" message type by construction, so a signature minted
# over another object type (a request signature, a revocation list) can never be
# reinterpreted as a cap-cert even if a future field change made their bodies
# overlap. Must stay byte-identical across TS, Python, and the vector generators.
_CAP_CERT_DOMAIN = "starfish-capcert-v1\n"


def cap_cert_canonical_signing_input(cert: dict[str, Any]) -> str:
    """Return the canonical UTF-8 string used as the issAlg signing input.

    The domain tag ``_CAP_CERT_DOMAIN`` followed by the cert with ``sig``
    stripped. The function accepts the cert dict with or without ``sig``; any
    ``sig`` key is stripped before serializing. The result is identical
    byte-for-byte to the TypeScript ``capCertCanonicalSigningInput``.
    """
    unsigned = {k: v for k, v in cert.items() if k != "sig"}
    return _CAP_CERT_DOMAIN + stable_stringify(unsigned)


# ── Signing & verification ────────────────────────────────────────────────────


def _user_id_from_pub_hex(pub_hex: str) -> str:
    """sha256(hexDecode(pub_hex))[0:32] — matches the TS implementation."""
    return hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:32]


def user_id_from_pub_hex(pub_hex: str) -> str:
    """Public alias of :func:`_user_id_from_pub_hex`.

    Derive a userId from an Ed25519 public key: ``sha256(hexDecode(pub_hex))[0:32]``.
    Exported so the server can bind an audience cap's presenter to their own
    identity (``auth.identity = user_id_from_pub_hex(presenter_pub_hex)``).
    """
    return _user_id_from_pub_hex(pub_hex)


def recipient_kem(cert: dict[str, Any]) -> tuple[str, str]:
    """Resolve a subject cap-cert's KEM recipient identity — the pubkey + suite
    the keyring seals collection keys to. Returns ``(kem_pub_hex, kem_alg)``.

    - ``kem_alg`` = the first of ``subKemAlg``, ``subAlg``, ``issAlg`` that is
      not ``None`` (KEM suite, defaulting through the signing suite to the
      issuer suite). Resolved with ``is None`` checks, NOT ``or`` — an empty
      string is a present (if invalid) tag and must not fall through.
    - ``kem_pub_hex`` = ``subKem`` if not ``None`` else ``sub`` — the dedicated KEM key when present
      (separate X25519 for ``ed25519``, or a mixed-pair KEM key), else the
      signing key itself (same-suite ``secp256k1-schnorr``, where ``sub`` doubles
      as the KEM key).

    Raises ``ValueError`` for a subject-less (``audience``) cap.
    """
    # Mirror TS `??` (only None falls through, not an empty string) so a present
    # subKem/subAlg is never silently replaced by sub/issAlg.
    kem_alg = cert.get("subKemAlg")
    if kem_alg is None:
        kem_alg = cert.get("subAlg")
    if kem_alg is None:
        kem_alg = cert["issAlg"]
    kem_pub_hex = cert.get("subKem")
    if kem_pub_hex is None:
        kem_pub_hex = cert.get("sub")
    if kem_pub_hex is None:
        raise ValueError("recipient_kem: cap binds no subject KEM key (audience cap?)")
    return (kem_pub_hex, kem_alg)


_GLOB_REGEX_SPECIALS = re.compile(r"[.+?^${}()|\[\]\\]")


def path_glob_match(glob: str, target: str) -> bool:
    """Glob match used for cap-cert path semantics.

    ``**`` matches any run of characters including slashes; a single ``*``
    matches any run of non-slash characters; all other regex specials are
    escaped literally. The pattern must match the entire ``target``. Mirrors
    the TS ``pathGlobMatch`` helper byte-for-byte.

    The ``**`` rule is mandatory for correctness: the server's request-path
    enforcement (``match_scope_path``) treats ``**`` as crossing slashes, so
    the member-cap scope barriers that decide whether a ``_keyring`` or
    ``_members`` deny is required must use the identical rule — a matcher that
    stopped ``**`` at a slash would clear a cap the resolver later grants.
    ``match_scope_path`` delegates here so the two cannot drift apart.

    Exported so extension packages that own kind-specific scope rules
    (``starfish_sharing``'s member-cap shape checks) reuse the exact same
    matcher the protocol uses.
    """
    out: list[str] = []
    i = 0
    n = len(glob)
    while i < n:
        ch = glob[i]
        if ch == "*" and i + 1 < n and glob[i + 1] == "*":
            out.append(".*")
            i += 2
        elif ch == "*":
            out.append("[^/]*")
            i += 1
        elif _GLOB_REGEX_SPECIALS.match(ch):
            out.append("\\" + ch)
            i += 1
        else:
            out.append(ch)
            i += 1
    return re.fullmatch("".join(out), target) is not None


def is_root_device_cap(cert: dict[str, Any]) -> bool:
    """True when ``cert`` is a self-signed device cap (issuer is its own subject).

    This is the signature of a **root device**: ``bootstrap_root_identity`` mints
    the first device's cap with ``iss == sub``, whereas every paired device is
    minted by the root with ``iss = root, sub = device`` (``iss != sub``), and
    member caps always bind a distinct subject. Callers use it to distinguish the
    root device from delegated devices/members (e.g. server-side root-only
    collections).

    Note: this only identifies a self-signed device cap; it does not by itself
    prove the cap belongs to a *particular* root identity. Cross-identity
    isolation comes from ``issUserId`` / ``{identity}`` path binding, not this
    check. Mirrors the TS ``isRootDeviceCap`` helper.
    """
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

# Required decoded length of a cap-cert ``nonce`` (matches the minted length).
_NONCE_LEN_BYTES = 16

# Upper bound on the number of entries in an audience cap's ``aud`` allow-list.
_MAX_AUDIENCE = 64

# An ``aud`` entry: a 64-char lowercase-hex Ed25519 pubkey. Use the ASCII class
# ``[0-9a-f]`` (not ``\d``/``\w``, which are Unicode-aware in Python) so the
# predicate matches the TS ``/^[0-9a-f]{64}$/`` byte-for-byte.
_AUD_ENTRY_RE = re.compile(r"[0-9a-f]{64}")


def _is_js_integer(value: Any) -> bool:
    # Mirror JavaScript's ``Number.isInteger``, which the TS side uses for
    # ``nbf``/``exp``. ``bool`` is rejected (a JSON boolean is not a timestamp).
    # A whole-number float (``1700000000.0``) is accepted: after JSON parsing JS
    # cannot distinguish it from the integer (both are the same IEEE-754 value),
    # so accepting it keeps the two languages in agreement. ``NaN``/``Infinity``
    # (e.g. from a literal ``1e400``) and fractional floats are rejected — a
    # non-integer ``exp`` would corrupt the ``now > exp + skew`` expiry gate.
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    if isinstance(value, float):
        return math.isfinite(value) and value.is_integer()
    return False


class CapCertVerifyResult(TypedDict, total=False):
    """Aggregate result of :func:`verify_cap_cert`."""

    ok: bool
    reason: str


class UnsignedCapCert(TypedDict):
    """Cap-cert without its signature — the value whose canonical
    stable-stringification is the issAlg signing input."""

    v: Literal[1]
    kind: CapKind
    issAlg: Alg
    subAlg: NotRequired[Alg]
    subKemAlg: NotRequired[Alg]
    iss: str
    issUserId: str
    sub: str
    subKem: NotRequired[str]
    subUserId: NotRequired[str]
    scope: CapScope
    nbf: int
    exp: int
    nonce: str


def assert_cap_cert_well_formed(cert: dict[str, Any]) -> None:
    """Generic, kind-agnostic cap-cert structural checks.

    Raises ``ValueError`` whose ``args[0]`` is one of:
    ``"iss-userid-mismatch"``, ``"sub-userid-mismatch"``.

    Rules (apply to every cap kind):

    - ``sha256(hexDecode(iss))[0:32]`` must equal ``issUserId``.
    - If ``subUserId`` is present, the same relation must hold for ``sub``.

    Kind-specific structural rules (e.g. the member-cap barriers
    ``member-self`` / ``member-private-path`` / ``member-members-not-denied``
    …) are owned by the extension that defines that kind — see
    ``assert_member_cap_shape`` in ``starfish_sharing``. The server enforces
    them through the extension's ``ServerPlugin`` validator; with strict-kind
    dispatch a cap whose kind has no registered validator is rejected.
    """
    # Runtime shape validation of attacker-supplied fields. A cap-cert arrives
    # as parsed JSON with no type guarantees, and the resolver feeds
    # ``scope["ops"]`` / ``scope["collections"]`` straight into role synthesis —
    # a string ``ops`` would be iterated character-by-character into fabricated
    # roles instead of failing closed. Validate the structure first.
    if cert.get("kind") not in ("device", "member", "audience"):
        raise ValueError("malformed-shape")
    if not is_alg(cert.get("issAlg")):
        raise ValueError("malformed-shape")
    is_audience = cert.get("kind") == "audience"
    for key in ("iss", "issUserId", "nonce"):
        if not isinstance(cert.get(key), str):
            raise ValueError("malformed-shape")
    # Subject binding is kind-specific. An audience cap binds no subject, so
    # ``subAlg``/``sub``/``subKem``/``subUserId`` MUST all be absent (PRESENCE
    # test, not ``is not None`` — an explicit JSON ``null`` is *present* and must
    # be rejected to match the TS ``!== undefined`` checks, else a cross-language
    # split). Device/member carry a subject: ``subAlg`` (a known suite) + ``sub``
    # are required, and ``subKem``'s presence is *suite-determined* — required
    # for a separate-KEM suite (ed25519 -> X25519), forbidden otherwise.
    if is_audience:
        if (
            "subAlg" in cert
            or "subKemAlg" in cert
            or "sub" in cert
            or "subKem" in cert
            or "subUserId" in cert
        ):
            raise ValueError("audience-has-sub")
    else:
        # ``subAlg`` (signing) and ``subKemAlg`` (KEM) are optional on the wire
        # (tolerant reader): absent ⇒ ``subAlg`` falls back to ``issAlg`` and
        # ``subKemAlg`` to ``subAlg``. Mint helpers emit ``subAlg`` (strict
        # writer); both are part of the signed bytes, so neither can be forged.
        if "subAlg" in cert and not is_alg(cert.get("subAlg")):
            raise ValueError("malformed-shape")
        if "subKemAlg" in cert and not is_alg(cert.get("subKemAlg")):
            raise ValueError("malformed-shape")
        sub_alg = cert.get("subAlg", cert["issAlg"])
        kem_alg = cert.get("subKemAlg", sub_alg)
        if not isinstance(cert.get("sub"), str):
            raise ValueError("malformed-shape")
        # ``subKem`` is absent ONLY when the KEM key *is* the signing key — KEM
        # suite == signing suite AND that suite reuses one key (secp256k1). Any
        # other combination carries a distinct KEM pubkey of suite ``kem_alg``.
        kem_key_is_sign_key = kem_alg == sub_alg and not suite_has_separate_kem(kem_alg)
        if kem_key_is_sign_key:
            if "subKem" in cert:
                raise ValueError("malformed-shape")
        elif not isinstance(cert.get("subKem"), str):
            raise ValueError("malformed-shape")
        # A self-signed device cap (iss == sub) must use one suite for both.
        if (
            cert.get("kind") == "device"
            and cert.get("iss") == cert.get("sub")
            and "subAlg" in cert
            and cert.get("issAlg") != cert.get("subAlg")
        ):
            raise ValueError("malformed-shape")
    if not _is_js_integer(cert.get("nbf")) or not _is_js_integer(cert.get("exp")):
        raise ValueError("malformed-shape")
    # Nonce must be standard base64 of exactly 16 bytes (the minted length).
    # Validated only as a string before, a self-issuer could mint caps sharing a
    # nonce or use a degenerate/empty one — weakening per-cap revocation (which
    # keys on the nonce) and the per-signature uniqueness it provides.
    try:
        nonce_bytes = base64.b64decode(cert["nonce"], validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("malformed-shape")
    if len(nonce_bytes) != _NONCE_LEN_BYTES:
        raise ValueError("malformed-shape")
    # PRESENCE test (not ``is not None``): an explicit ``subUserId: null`` is
    # *present* and must be rejected as malformed to match TS ``c.subUserId
    # !== undefined`` (else a cross-language split — Python would treat null as
    # "no binding" and skip the hash check below, while TS rejects the cert).
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

    # ``aud`` allow-list: valid only on an audience cap, optional, and when
    # present a non-empty, bounded, de-duplicated list of 64-char lowercase-hex
    # pubkeys. Its absence is the canonical encoding of "any identity may redeem".
    # Test key PRESENCE, not ``is not None`` — a present ``aud: null`` must be
    # handled identically to TS's ``c.aud !== undefined`` (audience → validated
    # by ``_assert_aud_list`` and rejected as a bad entry; non-audience →
    # ``non-audience-has-aud``). ``aud is not None`` would treat ``aud: null`` as
    # absent and silently accept it as an open link / valid non-audience cap.
    if is_audience:
        if "aud" in cert:
            _assert_aud_list(cert["aud"])
    elif "aud" in cert:
        raise ValueError("non-audience-has-aud")

    iss = cert["iss"]
    iss_user_id = cert["issUserId"]
    if _user_id_from_pub_hex(iss) != iss_user_id:
        raise ValueError("iss-userid-mismatch")

    # An audience cap has no subject, so this is skipped (``sub_user_id`` is
    # None). For device/member, ``sub`` was already validated as a string above.
    if sub_user_id is not None:
        if _user_id_from_pub_hex(cert["sub"]) != sub_user_id:
            raise ValueError("sub-userid-mismatch")


def _assert_aud_list(aud: Any) -> None:
    """Validate an audience cap's ``aud`` allow-list.

    Raises ``ValueError`` with a coded message on the first failure. Kept
    identical to the TS ``assertAudList`` so the two languages reject the exact
    same lists.
    """
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
    """Sign an unsigned cap-cert with the issuer's private key, using the suite
    named by ``cert["issAlg"]``.

    Returns a new dict identical to ``cert`` with a base64-encoded
    (standard, padded) ``sig`` field added.
    """
    unsigned = {k: v for k, v in cert.items() if k != "sig"}
    message = cap_cert_canonical_signing_input(unsigned).encode("utf-8")
    sig_bytes = get_suite(unsigned.get("issAlg")).sign(message, iss_priv_hex)
    return {**unsigned, "sig": base64.b64encode(sig_bytes).decode("ascii")}


def verify_cap_cert_signature(cert: dict[str, Any]) -> bool:
    """Return ``True`` iff ``cert["sig"]`` verifies against ``cert["iss"]``
    under the cert's declared ``alg``."""
    try:
        message = cap_cert_canonical_signing_input(cert).encode("utf-8")
        sig_bytes = base64.b64decode(cert["sig"])
        return get_suite(cert.get("issAlg")).verify(sig_bytes, message, cert["iss"])
    except Exception:
        # Never raise — fail closed to False on any decode/suite error.
        return False


def verify_cap_cert(
    cert: dict[str, Any],
    *,
    now: int,
    clock_skew_sec: int = 300,
) -> dict[str, Any]:
    """Orchestrated verification: time window + well-formedness + signature.

    Returns ``{"ok": True}`` on success, otherwise ``{"ok": False,
    "reason": <short code>}``.
    """
    # Well-formedness FIRST (includes runtime shape validation) so the
    # time-window comparisons below never run against a non-numeric
    # ``nbf``/``exp`` — a malformed cert fails closed with a structural reason
    # instead of raising a raw ``KeyError``/``TypeError``.
    try:
        assert_cap_cert_well_formed(cert)
    except ValueError as e:
        return {"ok": False, "reason": e.args[0] if e.args else "malformed"}
    # Reject an inverted (or zero-width) validity window before the time gates.
    # Without this, a cert whose ``exp`` is at or before ``nbf`` could still pass
    # both ``now < nbf - skew`` and ``now > exp + skew`` during the instant where
    # the skew margins overlap (``nbf - exp <= 2*skew``). ``exp`` must be strictly
    # after ``nbf``. (Follow-up: the mint helpers could also reject a negative
    # ``ttl_sec`` so such a cert is never produced in the first place.)
    if cert["exp"] <= cert["nbf"]:
        return {"ok": False, "reason": "inverted-window"}
    if now < cert["nbf"] - clock_skew_sec:
        return {"ok": False, "reason": "not-yet-valid"}
    if now > cert["exp"] + clock_skew_sec:
        return {"ok": False, "reason": "expired"}
    if not verify_cap_cert_signature(cert):
        return {"ok": False, "reason": "bad-signature"}
    return {"ok": True}
