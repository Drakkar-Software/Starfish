"""Device-code space-join pairing over ONE public rendezvous slot.

A generic "a client asks to join a space, a human approves, a cap is delivered"
primitive. It exists because neither existing join path covers it:
:func:`~starfish_spaces.members.create_space_invite_link` is a BEARER link (the
grant materializes at creation time, the whole credential rides in a URL
fragment, there is no approve-before-grant step), and
:func:`~starfish_spaces.members.make_join_request` has no transport at all.

The flow, all at the SAME storage path ``_pairing/session/{code}``
(:meth:`SpaceLayout.join_session_pull` / :meth:`~SpaceLayout.join_session_push`):

1. **Requester** (e.g. a website with no wallet of its own) generates a fresh
   EPHEMERAL device keypair, signs a proof-of-possession over
   ``{code, devEdPub, devKemPub}``, and publishes
   ``{v:1, phase:"request", …}`` with **create-only CAS** (``base_hash=None``) —
   only the first write to a fresh code's slot succeeds.
2. **Approver** (the space owner's device) pulls the slot by the short code the
   human typed, verifies ``popSig``, and shows ``origin``/``label`` for
   approval. Nothing is granted yet.
3. **Approver approves**: mints a member cap (via
   :func:`~starfish_spaces.members.invite_to_space`), seals it to ``devKemPub``
   with ``code`` as AAD, and **CAS-UPDATEs the SAME slot** to
   ``{v:1, phase:"grant", sealed:…}`` using the hash of the request doc it just
   read.
4. **Requester** polls the SAME slot; it resolves only once ``phase == "grant"``
   and unseals with its never-transmitted ``devKemPriv``.

Security invariants centralized here:

- **One address, two phases.** ``code`` is BOTH the discovery address AND the
  PoP-signature/AAD binding value. There is deliberately no separate
  high-entropy ``session_id``: it would add no confidentiality the KEM seal does
  not already provide (a slot keyed by a guessable code that contained a
  plaintext session id already leaked it for free), only lifecycle bookkeeping.
- **Confidentiality comes from the KEM seal, not from address entropy.** The
  slot is public-read by design; the grant is sealed to an ephemeral KEM public
  key whose private half never leaves the requester. Guessing a code exposes a
  pending request record (public keys + ``origin``) and an *unopenable*
  ciphertext, never a usable cap. This is why the merge to one slot is safe and
  why sealing must stay KEM-based — a PIN/passphrase seal would downgrade
  confidentiality to offline-brute-forceable code guessing.
- **Own-write CAS everywhere.** Each writer CASes against the hash IT last saw,
  never a freshly re-pulled one. A hostile overwrite therefore surfaces as a
  loud :class:`SpaceJoinConflictError`, instead of silently becoming the
  writer's new baseline. Notably this module does NOT use
  :func:`~starfish_spaces.cas_retry.run_cas` — blind conflict-retry is exactly
  the behavior these invariants exist to prevent.
- **Wall-clock-anchored TTL.** ``expiresAt``/``createdAt`` are NOT covered by
  ``popSig``, so anyone with the code can rewrite them. The cap is therefore
  enforced against THIS call's real wall clock, never against the request's own
  self-reported ``createdAt`` — see :func:`parse_space_join_request`.
- **TOFU sealer pinning.** ``sealed_by`` is the verified Ed25519 key that
  actually sealed the grant. Record it after the first successful fetch and pass
  it back as ``expected_sealer`` on every later poll.

The grant slot is **re-pollable** and is NOT auto-cleared after a successful
read — a live pairing is genuinely re-read over its lifetime. Only the
collection's TTL backstop and an explicit :func:`clear_space_join_grant` at
unpair time remove it.

Wire format is camelCase JSON in BOTH languages (``devEdPub``, not
``dev_ed_pub``) — byte-identical to the TypeScript ``join-request.ts`` twin,
matching how every other shared wire shape in this package is written (see
:mod:`starfish_spaces.token_types`). Python-side function and local names stay
snake_case.
"""

from __future__ import annotations

import asyncio
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Callable, Coroutine, Literal, Mapping, Optional, TypedDict
from urllib.parse import urlparse

from starfish_keyring import SealedBlob, seal, unseal
from starfish_protocol.suites import ed25519 as ed25519_suite
from starfish_sdk.types import ConflictError, StarfishHttpError

from starfish_identities import generate_device_keys

from starfish_spaces.client import make_anon_space_client
from starfish_spaces.config import SpaceLayout
from starfish_spaces.layout import default_space_layout, default_user_id_from_ed_pub
from starfish_spaces.request_verify import sign_kem_sig

if TYPE_CHECKING:
    from starfish_sdk import StarfishClient


# ── Code generation ───────────────────────────────────────────────────────────

CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
"""Excludes visually-ambiguous characters (0/O, 1/I/L) — Crockford-style, meant
to be read off one screen and typed on another. 31 symbols (23 letters + 8
digits); at :data:`CODE_LENGTH` characters that is ``8·log2(31) ≈ 39.63`` bits
of entropy, above RFC 8628's device-flow ``user_code`` minimum and bounded
further by the rendezvous collection's TTL and per-IP rate limit (neither of
which this package controls). :func:`random_code` uses rejection sampling, so
this figure is the real uniform entropy, not a biased approximation of it."""

CODE_LENGTH = 8
"""Number of characters in a human-typed join code."""

CODE_REJECT_THRESHOLD = (256 // len(CODE_ALPHABET)) * len(CODE_ALPHABET)
"""256 is not a multiple of 31 — a plain ``byte % 31`` would over-represent the
first ``256 % 31 = 8`` symbols (A-H) by 12.5% in every character position.
Reject any byte at or above the largest multiple of the alphabet length that
still fits in a byte (``248``) and draw a replacement: the remaining range
``[0, 248)`` maps onto the 31 symbols with exactly uniform probability."""

DEFAULT_REQUEST_TTL_SEC = 5 * 60
"""Default lifetime of a published join request."""

MAX_REQUEST_TTL_SEC = 60 * 60
"""Hard cap on a request's declared live window.

``expiresAt``/``createdAt`` are NOT covered by ``popSig`` — anyone with the code
can rewrite them, so a default nobody is forced to respect enforces nothing.
This is the real enforcement: :func:`parse_space_join_request` rejects a request
whose declared window exceeds this *relative to the parsing call's own wall
clock*, and :func:`create_space_join_request` clamps its own ``ttl_sec`` to it
so a well-meaning caller cannot build something this package would reject."""


def random_code() -> str:
    """Generate a fresh uniformly-distributed :data:`CODE_LENGTH`-character code."""
    chars: list[str] = []
    # Pull a batch at a time (rather than one byte per iteration) so a run of
    # rejected bytes doesn't turn into a syscall-per-byte loop — rejection hits
    # ~3% of bytes, so a fresh CODE_LENGTH-sized batch almost always finishes
    # the code outright, with a further batch only on the rare tail.
    while len(chars) < CODE_LENGTH:
        for b in secrets.token_bytes(CODE_LENGTH):
            if b >= CODE_REJECT_THRESHOLD:
                continue
            chars.append(CODE_ALPHABET[b % len(CODE_ALPHABET)])
            if len(chars) == CODE_LENGTH:
                break
    return "".join(chars)


# ── Wire types ────────────────────────────────────────────────────────────────


class Rendezvous(TypedDict):
    """Sync-server coordinates for the public rendezvous collection."""

    baseUrl: str
    namespace: str


class SpaceJoinRequestPayload(TypedDict, total=False):
    """Phase-``request`` document — the discovery half of the merged slot.

    Published by the requester under a code the human reads and types.
    Everything here is public by construction; nothing sensitive rides in it.
    """

    v: Literal[1]
    phase: Literal["request"]
    devEdPub: str
    """Ephemeral Ed25519 public key (hex). Never the requester's own identity."""
    devKemPub: str
    """Ephemeral X25519 KEM public key (hex) the grant gets sealed to."""
    popSig: str
    """``ed25519.sign(pop_signing_input(code, devEdPub, devKemPub), devEdPriv)``,
    hex. Binds the two public keys to THIS code and proves the requester holds
    ``devEdPriv``. It is not proof of the requester's identity or intent — which
    is exactly why ``origin``/``code`` remain what the approving human relies
    on."""
    joinRequestKemSig: str
    """``sign_kem_sig(devKemPub, devEdPriv)``, hex — a SEPARATE proof-of-possession
    over just ``devKemPub``, in the exact shape
    :func:`~starfish_spaces.invite_helpers.parse_join_request` expects. Lets the
    approver rebuild a join request from this payload alone (see
    :func:`join_request_from_space_join_request`) without the requester needing a
    full :class:`~starfish_spaces.session.Session` for an identity it has no
    wallet to derive."""
    origin: str
    """Attacker-controlled in the sense that anyone can put any string here — the
    approving side must VERIFY it (e.g. a ``.well-known`` fetch), not trust it at
    face value. This module only bounds and sanity-checks it as a string."""
    label: str
    requestedScopes: list[str]
    """Purely advisory: what the requester says it wants. The approver decides
    what to actually grant."""
    createdAt: str
    """ISO-8601. Informational ONLY — never used for a security decision."""
    expiresAt: str
    """ISO-8601. Checked against the parsing call's real wall clock."""


class SpaceJoinGrantDoc(TypedDict, total=False):
    """Phase-``grant`` document — the delivery half of the SAME slot."""

    v: Literal[1]
    phase: Literal["grant"]
    sealed: dict[str, Any]
    """A :class:`starfish_keyring.SealedBlob` dict, sealed to the request's
    ``devKemPub`` with the ``code`` as AAD."""
    grantedAt: str


GRANT_ENVELOPE_KIND = "starfish-space-join-grant"
GRANT_ENVELOPE_VERSION = 1
"""The sealed plaintext is ``{v, kind, spaceId, cap}`` — flat, not a nested
bundle string. Shared byte-for-byte with the TypeScript twin: a grant sealed by
one language must unseal in the other."""


# ── Errors ────────────────────────────────────────────────────────────────────


class SpaceJoinConflictError(ConflictError):
    """The rendezvous slot changed since this caller last wrote it.

    Treat as "this slot may have been tampered with", never as "retry against
    whatever is there now" — adopting the server's current hash is precisely how
    a hostile overwrite becomes the legitimate publisher's own new baseline.

    Subclasses :class:`~starfish_sdk.types.ConflictError` (rather than plain
    ``Exception``) so an ``except ConflictError`` — the convention every other
    CAS write in this package uses, and what the TS twin lets propagate
    untouched — still catches a join-request conflict instead of missing it.

    Caution: this cuts both ways. Because it IS a ``ConflictError``, wrapping
    a call that can raise this (``publish()``, ``publish_space_join_grant``,
    ``clear_space_join_grant``) in :func:`~starfish_spaces.cas_retry.run_cas`
    — or any other generic "retry on ConflictError" helper — would swallow it
    as an ordinary retriable conflict instead of surfacing the "treat this
    code as compromised" signal. None of this module's own call sites do
    that (each already IS the CAS operation, not a caller wrapping one), and
    they should not start.
    """

    def __init__(self, message: str = "") -> None:
        # Bypass ConflictError.__init__'s "hash_mismatch: …" formatting: this
        # error already carries its own full, specific message, and existing
        # callers/tests match against it directly.
        self.server_response = message
        Exception.__init__(self, message)


# ── Proof-of-possession ───────────────────────────────────────────────────────


def pop_signing_input(code: str, dev_ed_pub: str, dev_kem_pub: str) -> bytes:
    """Canonical bytes signed by ``popSig``.

    Binds ``devEdPub``/``devKemPub`` to THIS ``code`` so a signature cannot be
    replayed across a different (key-pair, code) combination. Byte-identical to
    the TypeScript twin's ``JSON.stringify({code, devEdPub, devKemPub})``:
    insertion-ordered keys, no whitespace.
    """
    return json.dumps(
        {"code": code, "devEdPub": dev_ed_pub, "devKemPub": dev_kem_pub},
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


# ── Creation (pure, no I/O) ───────────────────────────────────────────────────


@dataclass
class CreatedSpaceJoinRequest:
    """Result of :func:`create_space_join_request`."""

    request: SpaceJoinRequestPayload
    device: dict[str, str]
    """The fresh ephemeral ``{edPriv, edPub, kemPriv, kemPub}``. The PRIVATE
    halves never travel in ``request`` — they are what unseals the grant."""
    code: str
    """What the requester displays for a human to type. Also the slot address
    and the PoP/AAD binding value."""


def create_space_join_request(
    origin: str,
    *,
    label: Optional[str] = None,
    requested_scopes: Optional[list[str]] = None,
    ttl_sec: Optional[int] = None,
) -> CreatedSpaceJoinRequest:
    """Build a join request: fresh ephemeral keys, a PoP signature, a short code.

    Pure — performs no I/O. Use :func:`start_space_join_request` to also publish.

    Args:
        origin:           The requester's origin, shown to the approving human.
        label:            Optional human-readable requester name.
        requested_scopes: Advisory list of what the requester wants access to.
        ttl_sec:          Request lifetime. Clamped to :data:`MAX_REQUEST_TTL_SEC`
            — not merely defaulted, since a caller passing an oversized value
            would otherwise build a request :func:`parse_space_join_request`
            rejects outright, silently breaking their own integration. A NEGATIVE
            value is deliberately NOT clamped (it lets a test build an
            already-expired request); only the upper bound is enforced.

    Returns:
        A :class:`CreatedSpaceJoinRequest`.
    """
    device = generate_device_keys()
    code = random_code()
    effective_ttl = min(DEFAULT_REQUEST_TTL_SEC if ttl_sec is None else ttl_sec, MAX_REQUEST_TTL_SEC)
    now = datetime.now(timezone.utc)

    pop_sig = ed25519_suite.sign(
        pop_signing_input(code, device["edPub"], device["kemPub"]), device["edPriv"]
    ).hex()

    request: SpaceJoinRequestPayload = {
        "v": 1,
        "phase": "request",
        "devEdPub": device["edPub"],
        "devKemPub": device["kemPub"],
        "popSig": pop_sig,
        "joinRequestKemSig": sign_kem_sig(device["kemPub"], device["edPriv"]),
        "origin": origin,
    }
    if label is not None:
        request["label"] = label
    if requested_scopes is not None:
        request["requestedScopes"] = list(requested_scopes)
    request["createdAt"] = _iso(now)
    request["expiresAt"] = _iso(now + timedelta(seconds=effective_ttl))

    return CreatedSpaceJoinRequest(request=request, device=device, code=code)


def _iso(moment: datetime) -> str:
    """ISO-8601 with millisecond precision and a trailing ``Z``.

    Byte-identical in shape to JS ``Date.prototype.toISOString()``, so a
    timestamp this package writes round-trips through the TypeScript twin
    unchanged.
    """
    utc = moment.astimezone(timezone.utc)
    return f"{utc.strftime('%Y-%m-%dT%H:%M:%S')}.{utc.microsecond // 1000:03d}Z"


# ── Validation ────────────────────────────────────────────────────────────────

HEX_KEY_LENGTH = 64
"""Ed25519/X25519 public keys are 32 raw bytes ⇒ 64 hex characters."""

HEX_SIG_LENGTH = 128
"""An Ed25519 signature is 64 raw bytes ⇒ 128 hex characters."""

MAX_ORIGIN_LENGTH = 2048
MAX_LABEL_LENGTH = 200

UNSAFE_TEXT_PATTERN = re.compile(
    "[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]"
)
"""C0/C1 control characters (including ``\\n``/``\\r`` — a UI that renders an
embedded newline as a real line break lets attacker text masquerade as extra app
chrome) plus the Unicode bidi override/isolate controls (U+202A-E, U+2066-9)
that can visually reverse or reorder a rendered string, e.g. making a hostile
host read as a different one. Written as explicit escapes, never as literal
control/bidi characters in source."""

_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_SCHEME_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*")
_SPECIAL_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp"})
# WHATWG's URL parser strips leading/trailing C0-control-or-space before doing
# anything else. UNSAFE_TEXT_PATTERN already rejects embedded C0 controls
# elsewhere in `origin`, so in practice only plain leading/trailing space can
# reach here — but trimming the whole C0 range mirrors the spec exactly.
_LEADING_TRAILING_C0_SPACE_RE = re.compile(r"^[\x00-\x20]+|[\x00-\x20]+$")
# A "special" scheme (http/https/ws/wss/ftp) followed by a colon and ANY
# number of AUTHORITY-MARKER characters — WHATWG's "special authority ignore
# slashes" state treats a run of `/` AND `\` (mixed, any count, including
# zero) right after the colon as equivalent to `//`, e.g. `scheme:host`,
# `scheme:/host`, `scheme:\host`, `scheme://host`, `scheme:///host` all mean
# the same thing to `new URL()`.
_SPECIAL_SCHEME_AUTHORITY_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):[/\\]*(.*)$", re.DOTALL)
# WHATWG's host state ends the authority at the first `/`, `\`, `?`, or `#`
# (a rewrite-then-`urlparse` approach — the previous version of this function
# — can't replicate this: `urlparse` doesn't split on `\`, so it hands a
# padding space or a `\`-delimited fake userinfo straight through into what
# it reports as the hostname instead of rejecting/re-splitting it).
_AUTHORITY_TERMINATORS = frozenset("/\\?#")


def _special_scheme_authority_host(rest: str) -> str:
    """The WHATWG host for a special scheme, given everything after `scheme:`
    and any leading authority-marker slashes (see
    :data:`_SPECIAL_SCHEME_AUTHORITY_RE`) have already been stripped.

    Only computes enough to answer "is a well-formed, non-empty host present"
    — never returned or stored, so it does not need to be byte-identical to
    WHATWG's own host value, only accept/reject the same inputs it would.
    Splits userinfo off at the LAST `@` before the authority terminates (a
    literal user@ prefix, itself accepted by WHATWG, must not be mistaken for
    the host), and keeps an IPv6 literal's brackets together so a `:` inside
    them isn't mistaken for a port separator.
    """
    term_idx = next((i for i, ch in enumerate(rest) if ch in _AUTHORITY_TERMINATORS), len(rest))
    host_port = rest[:term_idx].rsplit("@", 1)[-1]
    if host_port.startswith("["):
        end = host_port.find("]")
        return host_port[: end + 1] if end != -1 else host_port
    return host_port.split(":", 1)[0]


def _assert_bounded_safe_text(value: str, field_name: str, max_length: int) -> None:
    if len(value) > max_length:
        raise ValueError(f"space join request: {field_name} exceeds max length")
    if UNSAFE_TEXT_PATTERN.search(value):
        raise ValueError(
            f"space join request: {field_name} contains a disallowed control or bidi-override character"
        )


def _assert_hex_length(value: str, field_name: str, expected_length: int) -> None:
    # Checked BEFORE any hex decode: decoding allocates proportionally to input
    # length with no ceiling of its own, so an unbounded hex string here would
    # allocate before ever reaching signature verification.
    if len(value) != expected_length or _HEX_RE.fullmatch(value) is None:
        raise ValueError(
            f"space join request: {field_name} is not a valid {expected_length}-character hex string"
        )


def _assert_valid_origin_url(origin: str) -> None:
    """Approximate WHATWG ``new URL()`` acceptance for the ``origin`` field.

    Requires a syntactically valid scheme, plus a non-empty, well-formed host
    for the "special" schemes (http/https/ws/wss/ftp) where WHATWG mandates
    one — computed via :func:`_special_scheme_authority_host`, WHATWG's own
    lenient authority-slash/backslash handling and userinfo/host/port
    splitting, since ``urlparse`` alone implements none of that. Non-special
    scheme-only forms WHATWG accepts (``mailto:a@b``) are accepted here too
    via a plain ``urlparse`` check, so the two languages agree on the inputs
    that actually reach signature verification.

    Leading/trailing C0-control-or-space is stripped first, mirroring another
    WHATWG normalization step ``urlparse`` doesn't perform on its own.

    ``origin`` is caller-controlled wire data — the two languages must reach
    the same accept/reject verdict on it, or a request one approver treats as
    well-formed another rejects outright (or, worse, the two silently
    disagree on WHICH host it names).
    """
    candidate = _LEADING_TRAILING_C0_SPACE_RE.sub("", origin)
    special_match = _SPECIAL_SCHEME_AUTHORITY_RE.match(candidate)
    if special_match and special_match.group(1).lower() in _SPECIAL_SCHEMES:
        host = _special_scheme_authority_host(special_match.group(2))
        if not host or " " in host:
            raise ValueError("space join request: origin is not a valid URL")
        return
    try:
        parsed = urlparse(candidate)
    except ValueError as exc:
        raise ValueError("space join request: origin is not a valid URL") from exc
    if not parsed.scheme or _SCHEME_RE.fullmatch(parsed.scheme) is None:
        raise ValueError("space join request: origin is not a valid URL")


def _parse_iso_ms(value: str) -> Optional[int]:
    """ISO-8601 → epoch milliseconds, or ``None`` when unparseable.

    Returning ``None`` (rather than raising or, worse, a NaN-like sentinel that
    compares false against everything) is what lets the caller FAIL CLOSED on a
    garbage timestamp instead of silently treating it as "not expired".
    """
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp() * 1000)


def parse_space_join_request(payload: str | Mapping[str, Any]) -> SpaceJoinRequestPayload:
    """Parse and validate a phase-``request`` document.

    Verifies the proof-of-possession signature and rejects an expired or
    over-long-lived request — both before the approving side does anything else
    with it. Does NOT verify that ``origin`` resolves to anything real; that
    needs a network check the approving side performs itself (this function stays
    I/O-free). It DOES bound and sanity-check ``origin``/``label``: a length cap,
    a URL parse for ``origin``, and rejection of control/bidi-override characters
    in both, since those are the two fields an approving human actually reads.
    Full homoglyph/IDNA-confusable host detection is out of scope.

    Args:
        payload: The document, as a JSON string or an already-parsed mapping.

    Returns:
        The validated :class:`SpaceJoinRequestPayload`.

    Raises:
        ValueError: on any structural, signature, or freshness failure.
    """
    if isinstance(payload, str):
        try:
            parsed: Any = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError("space join request: not valid JSON") from exc
    else:
        parsed = payload
    if not isinstance(parsed, Mapping):
        raise ValueError("space join request: not an object")

    if parsed.get("v") != 1 or parsed.get("phase") != "request":
        raise ValueError("space join request: not a phase-'request' payload")

    required = ("devEdPub", "devKemPub", "popSig", "joinRequestKemSig", "origin", "createdAt", "expiresAt")
    for name in required:
        if not isinstance(parsed.get(name), str):
            raise ValueError(f"space join request: malformed payload — {name}")
    if parsed.get("label") is not None and not isinstance(parsed.get("label"), str):
        raise ValueError("space join request: malformed payload — label")
    scopes = parsed.get("requestedScopes")
    if scopes is not None and (
        not isinstance(scopes, list) or any(not isinstance(s, str) for s in scopes)
    ):
        raise ValueError("space join request: malformed payload — requestedScopes")

    _assert_hex_length(parsed["devEdPub"], "devEdPub", HEX_KEY_LENGTH)
    _assert_hex_length(parsed["devKemPub"], "devKemPub", HEX_KEY_LENGTH)
    _assert_hex_length(parsed["popSig"], "popSig", HEX_SIG_LENGTH)
    _assert_hex_length(parsed["joinRequestKemSig"], "joinRequestKemSig", HEX_SIG_LENGTH)
    _assert_bounded_safe_text(parsed["origin"], "origin", MAX_ORIGIN_LENGTH)
    if parsed.get("label") is not None:
        _assert_bounded_safe_text(parsed["label"], "label", MAX_LABEL_LENGTH)
    _assert_valid_origin_url(parsed["origin"])

    request: SpaceJoinRequestPayload = dict(parsed)  # type: ignore[assignment]
    return request


def verify_space_join_request_pop(request: SpaceJoinRequestPayload, code: str) -> None:
    """Verify ``popSig`` binds this request's keys to ``code``, and enforce the TTL.

    Split out from :func:`parse_space_join_request` because in the merged
    single-slot design the code is the slot ADDRESS: the parser validates the
    document's shape, and only a caller that knows which code it pulled can check
    the binding. :func:`fetch_space_join_request_by_code` always calls both.

    Raises:
        ValueError: on an invalid PoP signature, an expired request, or a request
            claiming to stay valid longer than :data:`MAX_REQUEST_TTL_SEC` from
            now.
    """
    verified = ed25519_suite.verify(
        bytes.fromhex(request["popSig"]),
        pop_signing_input(code, request["devEdPub"], request["devKemPub"]),
        request["devEdPub"],
    )
    if not verified:
        raise ValueError("space join request: invalid proof-of-possession signature")

    now_ms = int(time.time() * 1000)
    expires_at_ms = _parse_iso_ms(request["expiresAt"])
    # A garbage expiresAt must be REJECTED, not silently treated as "not
    # expired" — fail closed.
    if expires_at_ms is None or expires_at_ms <= now_ms:
        raise ValueError("space join request: expired")

    # The actual enforcement of "short-lived code". expiresAt/createdAt are NOT
    # covered by popSig, so a party with the code can rewrite either to
    # anything. Comparing expiresAt against the request's OWN createdAt would be
    # trivially bypassable: an attacker controlling both can place them
    # arbitrarily far in the future while keeping their DIFFERENCE inside the
    # cap, making the code "look" freshly issued no matter when it is redeemed
    # (createdAt = now+364d, expiresAt = now+364d+1h passes a createdAt-relative
    # check yet keeps the code valid for the next year). Anchoring to THIS
    # CALL's real wall clock closes that: a request cannot claim to remain valid
    # more than MAX_REQUEST_TTL_SEC from right now, whatever it claims createdAt
    # to be. createdAt is otherwise purely informational.
    if expires_at_ms - now_ms > MAX_REQUEST_TTL_SEC * 1000:
        raise ValueError("space join request: expiry window exceeds the maximum this package allows")


# ── Rendezvous transport ──────────────────────────────────────────────────────


def _client_for(rendezvous: Rendezvous, override: Optional["StarfishClient"]) -> "StarfishClient":
    """The anonymous client for a rendezvous, or an injected one.

    ``override`` is the test/advanced seam (the TS twin uses a ``fetch``
    override; :func:`make_anon_space_client` takes no such hook, so injecting the
    whole client is the Python-side equivalent).
    """
    if override is not None:
        return override
    return make_anon_space_client(
        {"baseUrl": rendezvous["baseUrl"], "namespace": rendezvous["namespace"]}
    )


@dataclass
class RendezvousDoc:
    """A pulled rendezvous document plus the hash to CAS against."""

    data: dict[str, Any]
    hash: Optional[str]


async def _pull_slot(client: "StarfishClient", path: str) -> Optional[RendezvousDoc]:
    """Pull a rendezvous slot, or ``None`` when nothing is published there.

    An unwritten collection document does not necessarily 404 — depending on the
    deployment it pulls as the STRING ``"null"``, a raw ``None``, or an empty
    ``{}``. All of those, plus a genuine 404, are the not-found signal here.
    """
    try:
        result = await client.pull(path)
    except StarfishHttpError as exc:
        if exc.status == 404:
            return None
        raise
    data = getattr(result, "data", None)
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return None
    if not isinstance(data, dict) or not data:
        return None
    return RendezvousDoc(data=data, hash=getattr(result, "hash", None))


async def _pull_hash(client: "StarfishClient", path: str) -> Optional[str]:
    """The RAW hash at ``path``, whether or not the document is 'empty'.

    Deliberately not derived from :func:`_pull_slot`, which collapses an
    existing-but-empty ``{}`` doc down to ``None`` and discards its real hash.
    CASing ``None`` against a slot that DOES have a hash conflicts every time —
    that is what would make clearing an already-cleared slot permanently fail.
    """
    try:
        result = await client.pull(path)
    except StarfishHttpError as exc:
        if exc.status == 404:
            return None
        raise
    return getattr(result, "hash", None)


# ── Request side ──────────────────────────────────────────────────────────────


@dataclass
class StartSpaceJoinRequestOptions:
    """Arguments for :func:`start_space_join_request`."""

    origin: str
    rendezvous: Rendezvous
    label: Optional[str] = None
    requested_scopes: Optional[list[str]] = None
    ttl_sec: Optional[int] = None
    layout: Optional[SpaceLayout] = None
    """Path layout for the rendezvous slot. Defaults to
    :data:`~starfish_spaces.layout.default_space_layout` — this whole request
    half is resolvable session-lessly, mirroring
    ``complete_device_pairing``-style ``{rendezvous, layout}`` options rather
    than requiring a full :class:`~starfish_spaces.session.Session`."""
    client: Optional[Any] = None
    """Injected :class:`StarfishClient` (tests / custom transports)."""


@dataclass
class SpaceJoinRequestSession:
    """A requester's own end of a device-code space join.

    Carries its own ``rendezvous`` and ``layout`` so :func:`fetch_space_join_grant`
    / :func:`await_space_join_grant` take the session directly, with no
    re-spreading at the call site. There is deliberately no ``session_id`` field:
    ``code`` is the sole identifier in this design.
    """

    request: SpaceJoinRequestPayload
    device: dict[str, str]
    code: str
    rendezvous: Rendezvous
    layout: SpaceLayout = field(default=default_space_layout)
    client: Optional[Any] = None

    # This session's OWN remembered hash from its last successful publish. Starts
    # None so the FIRST publish() is create-only: it fails rather than silently
    # adopting whatever already occupies the slot. Every later publish() uses its
    # own remembered hash instead of re-pulling and trusting whatever the server
    # currently reports, so a hostile overwrite between two publishes surfaces as
    # a loud conflict instead of becoming this session's new baseline.
    _last_hash: Optional[str] = field(default=None, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    async def publish(self) -> None:
        """Publish (or re-publish) the request document to the rendezvous.

        Raises:
            SpaceJoinConflictError: the slot changed since this session's last
                write — treat the code as compromised, do not retry past it.
        """
        # Serializes overlapping publish() calls on the SAME session. Without
        # it, two in-flight calls both read the same _last_hash before either
        # awaits, so whichever the server processes second gets a real conflict
        # caused only by this session's own overlapping write — indistinguishable
        # from the third-party tampering the error is meant to report.
        async with self._lock:
            client = _client_for(self.rendezvous, self.client)
            path = self.layout.join_session_push(self.code)
            try:
                result = await client.push(path, dict(self.request), self._last_hash)
            except ConflictError as exc:
                raise SpaceJoinConflictError(
                    "space join request was modified by another party — treat this code as compromised"
                ) from exc
            self._last_hash = getattr(result, "hash", None)


async def start_space_join_request(
    opts: StartSpaceJoinRequestOptions,
) -> SpaceJoinRequestSession:
    """Requester side, step 1: create and publish a join request.

    The first :meth:`SpaceJoinRequestSession.publish` is create-only CAS
    (``base_hash=None``), so only the first write to a fresh code's slot
    succeeds.

    Example::

        rendezvous = {"baseUrl": "https://sync.example/sync", "namespace": "dk"}
        session = await start_space_join_request(
            StartSpaceJoinRequestOptions(origin="https://myapp.example", rendezvous=rendezvous)
        )
        await session.publish()
        show_code_to_user(session.code)
        grant = await await_space_join_grant(session)
    """
    created = create_space_join_request(
        opts.origin,
        label=opts.label,
        requested_scopes=opts.requested_scopes,
        ttl_sec=opts.ttl_sec,
    )
    return SpaceJoinRequestSession(
        request=created.request,
        device=created.device,
        code=created.code,
        rendezvous=opts.rendezvous,
        layout=opts.layout or default_space_layout,
        client=opts.client,
    )


@dataclass
class FetchSpaceJoinRequestOptions:
    """Arguments for :func:`fetch_space_join_request_by_code`."""

    code: str
    rendezvous: Rendezvous
    layout: Optional[SpaceLayout] = None
    client: Optional[Any] = None


@dataclass
class FetchedSpaceJoinRequest:
    """A validated request plus the slot hash needed to CAS the grant onto it."""

    request: SpaceJoinRequestPayload
    hash: Optional[str]
    """The hash of the request document just read. Pass it as
    :attr:`PublishSpaceJoinGrantOptions.base_hash` — the grant is a CAS UPDATE of
    this very document, not a fresh create."""


async def fetch_space_join_request_by_code(
    opts: FetchSpaceJoinRequestOptions,
) -> Optional[FetchedSpaceJoinRequest]:
    """Approver side, step 1: look up a request by the code the human typed.

    Returns ``None`` when nothing is published under that code at all (wrong
    code, or the collection's TTL already reclaimed it), and also when the slot
    has already advanced to ``phase="grant"`` — there is no pending request to
    approve in either case. A request that IS still present but expired or
    tampered with does NOT return ``None``; it raises, so the caller can tell
    "wrong code" apart from "right code, but it expired" and say so accurately.

    Returns the document's current hash alongside the parsed request: that hash
    is exactly what :func:`publish_space_join_grant` needs as its CAS
    ``base_hash``, and taking it from the same read that produced the request is
    what makes the grant write a genuine pull-then-push update.

    Raises:
        ValueError: the slot holds a phase-``request`` document that is
            malformed, expired, or not correctly signed for this code.
    """
    layout = opts.layout or default_space_layout
    client = _client_for(opts.rendezvous, opts.client)
    doc = await _pull_slot(client, layout.join_session_pull(opts.code))
    if doc is None:
        return None
    # Behavior deliberately matched to the TypeScript twin: an already-approved
    # slot is "nothing to approve", not an error.
    if doc.data.get("phase") != "request":
        return None
    request = parse_space_join_request(doc.data)
    verify_space_join_request_pop(request, opts.code)
    return FetchedSpaceJoinRequest(request=request, hash=doc.hash)


# ── Grant side ────────────────────────────────────────────────────────────────


@dataclass
class PublishSpaceJoinGrantOptions:
    """Arguments for :func:`publish_space_join_grant`."""

    request: SpaceJoinRequestPayload
    code: str
    """The slot address AND the seal's AAD. Anti-relocation: a grant sealed under
    one code cannot be replayed at another code's slot."""
    space_id: str
    """The space the requester is being admitted to."""
    cap: Any
    """The member cap minted for the requester's ephemeral identity — e.g.
    ``json.loads(await invite_to_space(...))["cap"]``. Sealed, never written in
    the clear."""
    sealer: Mapping[str, str]
    """The approver's ``{edPriv, edPub}``. Its ``edPub`` becomes the grant's
    verified ``sealed_by``, which the requester TOFU-pins."""
    rendezvous: Rendezvous
    """The approver's OWN trusted server config — the same one it used to look
    the request up. Never a value carried inside the request document: that rides
    in a doc anyone can publish to a public collection, so trusting it would let
    a malicious requester aim this device's outbound write at a host of its
    choosing. (This is why :class:`SpaceJoinRequestPayload` carries no
    ``rendezvous`` field at all.)"""
    base_hash: str
    """The hash of the request document just read
    (:attr:`FetchedSpaceJoinRequest.hash`). REQUIRED: the grant is a CAS UPDATE
    of the existing request document, never a create."""
    layout: Optional[SpaceLayout] = None
    client: Optional[Any] = None


async def publish_space_join_grant(opts: PublishSpaceJoinGrantOptions) -> Optional[str]:
    """Approver side, step 2: seal the minted cap and CAS-UPDATE the slot.

    Transitions the SAME document from ``phase="request"`` to ``phase="grant"``.

    Returns:
        The resulting hash, so a caller that legitimately republishes later can
        pass back the hash THIS call returned rather than re-deriving whatever is
        currently at the slot (an attacker's overwrite looks exactly like
        "whatever is currently there" too).

    Raises:
        ValueError: ``base_hash`` is missing — that would make this a create, and
            a grant must only ever replace a request it actually read.
        SpaceJoinConflictError: the slot changed since ``base_hash`` was read.
    """
    if not opts.base_hash:
        raise ValueError(
            "publish_space_join_grant: base_hash is required — a grant is a CAS UPDATE of the "
            "request document just read, never a create-only write into an empty slot"
        )

    layout = opts.layout or default_space_layout
    client = _client_for(opts.rendezvous, opts.client)

    envelope = {
        "v": GRANT_ENVELOPE_VERSION,
        "kind": GRANT_ENVELOPE_KIND,
        "spaceId": opts.space_id,
        "cap": opts.cap,
    }
    sealed = seal(
        json.dumps(envelope, separators=(",", ":"), ensure_ascii=False),
        opts.request["devKemPub"],
        sealer_ed_priv_hex=opts.sealer["edPriv"],
        sealer_ed_pub_hex=opts.sealer["edPub"],
        aad=opts.code,
    )
    doc: SpaceJoinGrantDoc = {
        "v": 1,
        "phase": "grant",
        "sealed": sealed.to_dict(),
        "grantedAt": _iso(datetime.now(timezone.utc)),
    }
    try:
        result = await client.push(layout.join_session_push(opts.code), dict(doc), opts.base_hash)
    except ConflictError as exc:
        raise SpaceJoinConflictError(
            "space join grant slot was modified by another party since the request was read — "
            "this pairing may be compromised"
        ) from exc
    return getattr(result, "hash", None)


@dataclass
class ClearSpaceJoinGrantOptions:
    """Arguments for :func:`clear_space_join_grant`."""

    code: str
    rendezvous: Rendezvous
    layout: Optional[SpaceLayout] = None
    client: Optional[Any] = None


_MAX_CLEAR_ATTEMPTS = 3


async def clear_space_join_grant(opts: ClearSpaceJoinGrantOptions) -> Optional[str]:
    """Approver side: overwrite the slot with an empty document at unpair time.

    Explicit cleanup, never automatic — the grant slot is re-pollable for the
    life of the pairing (see the module docstring), and the collection's TTL is
    an outer backstop, not a substitute for clearing.

    This is the ONE place blind-overwrite-and-retry is correct: unpairing must
    succeed even without a remembered hash (in-memory state lost across a
    restart), and "did someone else already overwrite this" is not a meaningful
    question when the caller's whole intent is "nothing should be published here
    anymore".

    Clearing does not recall a grant a requester already fetched. Real revocation
    is :func:`~starfish_spaces.members.remove_space_member` /
    :func:`~starfish_spaces.members.revoke_space_access`, which this complements
    rather than replaces: it only stops the CODE from resolving to a usable grant
    again.

    Returns:
        The resulting hash — same shape as :func:`publish_space_join_grant`.
    """
    layout = opts.layout or default_space_layout
    client = _client_for(opts.rendezvous, opts.client)
    pull_path = layout.join_session_pull(opts.code)
    push_path = layout.join_session_push(opts.code)

    last: Optional[ConflictError] = None
    for _ in range(_MAX_CLEAR_ATTEMPTS):
        current_hash = await _pull_hash(client, pull_path)
        try:
            result = await client.push(push_path, {}, current_hash)
        except ConflictError as exc:
            last = exc
            continue
        return getattr(result, "hash", None)
    raise SpaceJoinConflictError(
        f"clear_space_join_grant: too many base-hash conflicts at {pull_path}"
    ) from last


@dataclass
class SpaceJoinGrant:
    """An unsealed grant. Domain object — snake_case, unlike the camelCase wire."""

    space_id: str
    cap: Any
    """A real ``space:member`` cap for the requester's ephemeral device."""
    sealed_by: str
    """The Ed25519 pubkey that ACTUALLY sealed this grant, verified via the wrap
    entry's signature (never merely claimed). A trust-on-first-use pin: record it
    after the first successful fetch and pass it back as ``expected_sealer`` on
    every later poll, so a later writer to the same slot cannot silently replace
    an established pairing's grant with their own. Nothing pins WHO this key
    belongs to on the very first read — that trust comes from the human
    code/origin exchange."""


@dataclass
class FetchSpaceJoinGrantOptions:
    """Arguments for :func:`fetch_space_join_grant`."""

    expected_sealer: Optional[str] = None
    """TOFU pin — see :attr:`SpaceJoinGrant.sealed_by`."""


async def fetch_space_join_grant(
    session: SpaceJoinRequestSession,
    opts: Optional[FetchSpaceJoinGrantOptions] = None,
) -> Optional[SpaceJoinGrant]:
    """Requester side: read and unseal whatever grant is published at the slot.

    Phase-gated: returns ``None`` while the slot is empty or has not yet
    advanced past ``phase="request"`` (nobody has approved). A caller polling in
    a loop treats ``None`` as "keep waiting", not as a failure. A slot that IS a
    grant but fails to unseal raises instead — that is a real integrity signal,
    not a wait state.

    Deliberately does NOT read any space content — that stays the caller's job.

    Raises:
        ValueError: the slot is a grant whose envelope is malformed, whose seal
            does not open (wrong AAD ⇒ a relocated grant, wrong recipient, or
            tampering), or whose sealer does not match ``expected_sealer``.
    """
    opts = opts or FetchSpaceJoinGrantOptions()
    client = _client_for(session.rendezvous, session.client)
    doc = await _pull_slot(client, session.layout.join_session_pull(session.code))
    if doc is None:
        return None

    # Behavior deliberately matched to the TypeScript twin: anything that is not
    # yet a grant is a wait state, never an error.
    if doc.data.get("phase") != "grant":
        return None

    sealed_raw = doc.data.get("sealed")
    if not isinstance(sealed_raw, dict) or not isinstance(sealed_raw.get("entry"), dict):
        raise ValueError("space join grant: malformed sealed blob at this code's slot")

    sealed = SealedBlob.from_dict(sealed_raw)
    plaintext = unseal(
        sealed,
        session.device["kemPriv"],
        require_sealer=opts.expected_sealer,
        # The code, not the slot path: a grant sealed for one code cannot be
        # lifted into another code's slot and still open.
        aad=session.code,
    )
    try:
        envelope = json.loads(plaintext.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("space join grant: malformed grant envelope") from exc
    if (
        not isinstance(envelope, dict)
        or envelope.get("v") != GRANT_ENVELOPE_VERSION
        or envelope.get("kind") != GRANT_ENVELOPE_KIND
        or not isinstance(envelope.get("spaceId"), str)
        or envelope.get("cap") is None
    ):
        raise ValueError("space join grant: malformed grant envelope")

    return SpaceJoinGrant(
        space_id=envelope["spaceId"],
        cap=envelope["cap"],
        sealed_by=sealed.entry.added_by,
    )


@dataclass
class AwaitSpaceJoinGrantOptions:
    """Arguments for :func:`await_space_join_grant`."""

    timeout_sec: float = 5 * 60
    expected_sealer: Optional[str] = None
    poll_delay: Optional[Callable[[int], float]] = None
    """``(attempt) -> seconds``. Defaults to :func:`default_poll_delay`."""


POLL_MIN_SEC = 1.0
POLL_MAX_SEC = 5.0


def default_poll_delay(attempt: int) -> float:
    """Capped exponential backoff in seconds: ``min(1 · 2**attempt, 5)``.

    Matches the TypeScript twin's ``pollDelay`` so both sides put the same load
    on the rendezvous.
    """
    return min(POLL_MIN_SEC * 2**attempt, POLL_MAX_SEC)


async def await_space_join_grant(
    session: SpaceJoinRequestSession,
    opts: Optional[AwaitSpaceJoinGrantOptions] = None,
) -> SpaceJoinGrant:
    """Requester side: poll until the approver publishes a grant, or time out.

    This is the initial-approval wait, not an ongoing refresh loop — for later
    refreshes call :func:`fetch_space_join_grant` directly.

    A :func:`fetch_space_join_grant` failure (a network blip, a transient server
    error) does NOT end the wait: it is retried on the next tick, exactly like a
    ``None`` for "nothing published yet". Only the deadline ends it — with the
    last error if there was one (more informative than a bare timeout), else a
    generic :class:`TimeoutError`.

    The ONE exception to "swallow and keep polling": every failure
    :func:`fetch_space_join_grant` itself raises (malformed sealed blob,
    malformed envelope, an ``unseal`` rejection) is a :class:`ValueError` —
    a real integrity signal, not a wait state — and reraises immediately
    instead of being retried to the deadline. Retrying it would just keep
    re-reading the same bad document every cycle.
    """
    opts = opts or AwaitSpaceJoinGrantOptions()
    fetch_opts = FetchSpaceJoinGrantOptions(expected_sealer=opts.expected_sealer)
    delay_for = opts.poll_delay or default_poll_delay
    deadline = time.monotonic() + opts.timeout_sec
    last_err: Optional[BaseException] = None

    attempt = 0
    while True:
        try:
            result = await fetch_space_join_grant(session, fetch_opts)
            if result is not None:
                return result
        except ValueError:
            raise
        except Exception as exc:  # noqa: BLE001 — retried until the deadline
            last_err = exc
        if time.monotonic() >= deadline:
            if last_err is not None:
                raise TimeoutError(
                    "timed out waiting for the space join to be approved"
                ) from last_err
            raise TimeoutError("timed out waiting for the space join to be approved")
        await asyncio.sleep(delay_for(attempt))
        attempt += 1


# ── Bridge to the existing invite flow ────────────────────────────────────────


async def join_request_from_space_join_request(
    request: SpaceJoinRequestPayload,
    user_id_from_ed_pub: Optional[Callable[[str], Coroutine[Any, Any, str]]] = None,
) -> str:
    """Rebuild the join-request JSON :func:`~starfish_spaces.members.invite_to_space` expects.

    Sibling of :func:`~starfish_spaces.members.make_join_request`, which builds
    the same ``{edPub, kemPub, userId, kemSig}`` shape from a
    :class:`~starfish_spaces.session.Session`. This one builds it from a join
    request's already-public ``devEdPub``/``devKemPub`` plus the
    ``joinRequestKemSig`` it carries, so the requester never needs a full
    ``Session`` for an identity it has no wallet to derive.

    Args:
        request: A request already validated by
            :func:`parse_space_join_request` (and, when it came off the wire,
            :func:`verify_space_join_request_pop`).
        user_id_from_ed_pub: Override for userId derivation. Defaults to
            :func:`~starfish_spaces.layout.default_user_id_from_ed_pub`; pass the
            session's own hook when the app configured a custom one, so the
            derived userId matches what the roster will contain.

    Returns:
        The join-request JSON string, ready for ``invite_to_space``.
    """
    derive = user_id_from_ed_pub or default_user_id_from_ed_pub
    user_id = await derive(request["devEdPub"])
    return json.dumps(
        {
            "edPub": request["devEdPub"],
            "kemPub": request["devKemPub"],
            "userId": user_id,
            "kemSig": request["joinRequestKemSig"],
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )


__all__ = [
    # constants
    "CODE_ALPHABET",
    "CODE_LENGTH",
    "CODE_REJECT_THRESHOLD",
    "DEFAULT_REQUEST_TTL_SEC",
    "MAX_REQUEST_TTL_SEC",
    "HEX_KEY_LENGTH",
    "HEX_SIG_LENGTH",
    "MAX_ORIGIN_LENGTH",
    "MAX_LABEL_LENGTH",
    "UNSAFE_TEXT_PATTERN",
    "GRANT_ENVELOPE_KIND",
    "GRANT_ENVELOPE_VERSION",
    "POLL_MIN_SEC",
    "POLL_MAX_SEC",
    # types
    "Rendezvous",
    "SpaceJoinRequestPayload",
    "SpaceJoinGrantDoc",
    "SpaceJoinConflictError",
    "CreatedSpaceJoinRequest",
    "RendezvousDoc",
    "StartSpaceJoinRequestOptions",
    "SpaceJoinRequestSession",
    "FetchSpaceJoinRequestOptions",
    "FetchedSpaceJoinRequest",
    "PublishSpaceJoinGrantOptions",
    "ClearSpaceJoinGrantOptions",
    "SpaceJoinGrant",
    "FetchSpaceJoinGrantOptions",
    "AwaitSpaceJoinGrantOptions",
    # functions
    "random_code",
    "pop_signing_input",
    "create_space_join_request",
    "parse_space_join_request",
    "verify_space_join_request_pop",
    "start_space_join_request",
    "fetch_space_join_request_by_code",
    "publish_space_join_grant",
    "clear_space_join_grant",
    "fetch_space_join_grant",
    "default_poll_delay",
    "await_space_join_grant",
    "join_request_from_space_join_request",
]
