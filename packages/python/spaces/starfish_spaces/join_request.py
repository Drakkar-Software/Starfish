"""Device-code space-join pairing over ONE public rendezvous slot.

A client asks to join a space, a human approves, a cap is delivered. Both phases
live at the SAME path ``_pairing/session/{code}``
(:meth:`SpaceLayout.join_session_pull` / :meth:`~SpaceLayout.join_session_push`):
the requester publishes ``{v:1, phase:"request", …}`` with create-only CAS, the
approver CAS-UPDATEs that same document to ``{v:1, phase:"grant", …}`` with a cap
sealed to the requester's ephemeral KEM key, and the requester polls until it can
unseal it.

Security invariants:

- **One address, two phases.** ``code`` is BOTH the discovery address AND the
  PoP-signature/AAD binding value. A separate high-entropy ``session_id`` would
  add no confidentiality the KEM seal does not already provide.
- **Confidentiality comes from the KEM seal, not address entropy.** The slot is
  public-read; guessing a code exposes public keys plus an unopenable
  ciphertext, never a usable cap. Sealing must stay KEM-based: a PIN/passphrase
  seal would downgrade this to offline-brute-forceable code guessing.
- **Own-write CAS everywhere.** Each writer CASes against the hash IT last saw,
  never a freshly re-pulled one, so a hostile overwrite surfaces as a loud
  :class:`SpaceJoinConflictError` instead of becoming the writer's new baseline.
  This module deliberately does NOT use :func:`~starfish_spaces.cas_retry.run_cas`.
- **Wall-clock-anchored TTL.** ``expiresAt``/``createdAt`` are NOT covered by
  ``popSig``, so the cap is enforced against THIS call's real wall clock.
- **TOFU sealer pinning.** ``sealed_by`` is the verified Ed25519 key that
  actually sealed the grant; pass it back as ``expected_sealer`` on later polls.

The grant slot is re-pollable and NOT auto-cleared after a successful read; only
the collection's TTL and an explicit :func:`clear_space_join_grant` remove it.

Wire format is camelCase JSON in BOTH languages, byte-identical to the
TypeScript ``join-request.ts`` twin. Python-side names stay snake_case.
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
"""Crockford-style: excludes visually-ambiguous 0/O and 1/I/L. 31 symbols at
:data:`CODE_LENGTH` characters is ``8·log2(31) ≈ 39.63`` bits, above RFC 8628's
device-flow ``user_code`` minimum."""

CODE_LENGTH = 8

CODE_REJECT_THRESHOLD = (256 // len(CODE_ALPHABET)) * len(CODE_ALPHABET)
"""256 is not a multiple of 31, so a plain ``byte % 31`` would over-represent
A-H by 12.5%. Reject bytes at or above 248 and redraw: ``[0, 248)`` maps onto
the 31 symbols with exactly uniform probability."""

DEFAULT_REQUEST_TTL_SEC = 5 * 60

MAX_REQUEST_TTL_SEC = 60 * 60
"""Hard cap on a request's declared live window. ``expiresAt`` is not covered by
``popSig``, so this is the real enforcement: :func:`parse_space_join_request`
rejects a window exceeding it relative to the parsing call's own wall clock, and
:func:`create_space_join_request` clamps ``ttl_sec`` so a caller cannot build a
request this package would reject."""


def random_code() -> str:
    """Generate a fresh uniformly-distributed :data:`CODE_LENGTH`-character code."""
    chars: list[str] = []
    # Batched so a run of rejected bytes doesn't become a syscall per byte.
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
    """Phase-``request`` document. Everything here is public by construction."""

    v: Literal[1]
    phase: Literal["request"]
    devEdPub: str
    """Ephemeral Ed25519 public key (hex). Never the requester's own identity."""
    devKemPub: str
    """Ephemeral X25519 KEM public key (hex) the grant gets sealed to."""
    popSig: str
    """``ed25519.sign(pop_signing_input(code, devEdPub, devKemPub), devEdPriv)``,
    hex. Binds the keys to THIS code; not proof of the requester's identity or
    intent, which is why ``origin``/``code`` remain what the human relies on."""
    joinRequestKemSig: str
    """``sign_kem_sig(devKemPub, devEdPriv)``, hex. A separate PoP over just
    ``devKemPub``, in the shape
    :func:`~starfish_spaces.invite_helpers.parse_join_request` expects, so the
    approver can rebuild a join request from this payload alone."""
    origin: str
    """Anyone can put any string here, so the approving side must VERIFY it (e.g.
    a ``.well-known`` fetch), not trust it at face value."""
    label: str
    requestedScopes: list[str]
    """Advisory only. The approver decides what to actually grant."""
    createdAt: str
    """ISO-8601. Informational ONLY, never used for a security decision."""
    expiresAt: str
    """ISO-8601. Checked against the parsing call's real wall clock."""


class SpaceJoinGrantDoc(TypedDict, total=False):
    """Phase-``grant`` document: the delivery half of the SAME slot."""

    v: Literal[1]
    phase: Literal["grant"]
    sealed: dict[str, Any]
    """A :class:`starfish_keyring.SealedBlob` dict, sealed to the request's
    ``devKemPub`` with the ``code`` as AAD."""
    grantedAt: str


GRANT_ENVELOPE_KIND = "starfish-space-join-grant"
GRANT_ENVELOPE_VERSION = 1
"""The sealed plaintext is ``{v, kind, spaceId, cap}``, shared byte-for-byte
with the TypeScript twin: a grant sealed by one language must unseal in the
other."""


# ── Errors ────────────────────────────────────────────────────────────────────


class SpaceJoinConflictError(ConflictError):
    """The rendezvous slot changed since this caller last wrote it.

    Means "this slot may have been tampered with", never "retry against whatever
    is there now". Because it IS a :class:`~starfish_sdk.types.ConflictError`,
    wrapping a raiser in :func:`~starfish_spaces.cas_retry.run_cas` would swallow
    it as an ordinary retriable conflict. No call site here does that.
    """

    def __init__(self, message: str = "") -> None:
        # Bypass ConflictError.__init__'s "hash_mismatch: …" prefix: callers and
        # tests match this message directly.
        self.server_response = message
        Exception.__init__(self, message)


# ── Proof-of-possession ───────────────────────────────────────────────────────


def pop_signing_input(code: str, dev_ed_pub: str, dev_kem_pub: str) -> bytes:
    """Canonical bytes signed by ``popSig``, byte-identical to the twin's
    ``JSON.stringify({code, devEdPub, devKemPub})``: insertion-ordered, no
    whitespace. Binding to THIS ``code`` is what stops signature replay under a
    different (key-pair, code) pair."""
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
    """The fresh ephemeral ``{edPriv, edPub, kemPriv, kemPub}``. The private
    halves never travel in ``request``; they are what unseals the grant."""
    code: str
    """Displayed for a human to type. Also the slot address and PoP/AAD binding."""


def create_space_join_request(
    origin: str,
    *,
    label: Optional[str] = None,
    requested_scopes: Optional[list[str]] = None,
    ttl_sec: Optional[int] = None,
) -> CreatedSpaceJoinRequest:
    """Build a join request: fresh ephemeral keys, a PoP signature, a short code.

    Pure, no I/O. Use :func:`start_space_join_request` to also publish.
    ``ttl_sec`` is clamped to :data:`MAX_REQUEST_TTL_SEC`, not merely defaulted,
    so an oversized value cannot build a request the parser would reject. A
    NEGATIVE value is deliberately not clamped, to allow expired-request tests.
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
    """ISO-8601 with millisecond precision and a trailing ``Z``, matching JS
    ``Date.prototype.toISOString()`` so timestamps round-trip through the twin."""
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
"""C0/C1 controls (including ``\\n``/``\\r``, which a UI renders as a real line
break, letting attacker text masquerade as app chrome) plus the Unicode bidi
override/isolate controls that can visually reorder a rendered host. Written as
explicit escapes, never as literal control characters in source."""

_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_SCHEME_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*")
_SPECIAL_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp"})
# WHATWG strips leading/trailing C0-control-or-space before parsing anything.
_LEADING_TRAILING_C0_SPACE_RE = re.compile(r"^[\x00-\x20]+|[\x00-\x20]+$")
# WHATWG's "special authority ignore slashes" state treats any run of `/` and
# `\` after `scheme:` (mixed, any count, including zero) as `//`, so
# `scheme:host`, `scheme:\host` and `scheme:///host` all name the same host.
_SPECIAL_SCHEME_AUTHORITY_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):[/\\]*(.*)$", re.DOTALL)
# WHATWG's host state ends the authority at the first of these. `urlparse` does
# not split on `\`, so it would hand a `\`-delimited fake userinfo straight
# through as the hostname.
_AUTHORITY_TERMINATORS = frozenset("/\\?#")


def _special_scheme_authority_host(rest: str) -> str:
    """The WHATWG host, given everything after ``scheme:`` and its authority
    slashes. Only needs to accept/reject what WHATWG does, not match its host
    byte for byte. Userinfo splits at the LAST ``@`` before the authority ends,
    and IPv6 brackets stay together so an inner ``:`` isn't read as a port."""
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
    # length with no ceiling of its own.
    if len(value) != expected_length or _HEX_RE.fullmatch(value) is None:
        raise ValueError(
            f"space join request: {field_name} is not a valid {expected_length}-character hex string"
        )


def _assert_valid_origin_url(origin: str) -> None:
    """Approximate WHATWG ``new URL()`` acceptance for ``origin``, so both
    languages reach the same verdict on this caller-controlled field.
    ``urlparse`` implements none of WHATWG's authority-slash, backslash or
    userinfo handling, hence the hand-rolled path for the special schemes that
    mandate a host; scheme-only forms (``mailto:a@b``) go through ``urlparse``."""
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

    ``None`` rather than a NaN-like sentinel is what lets the caller fail CLOSED
    on a garbage timestamp instead of reading it as "not expired".
    """
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp() * 1000)


def parse_space_join_request(payload: str | Mapping[str, Any]) -> SpaceJoinRequestPayload:
    """Parse and validate a phase-``request`` document, raising ``ValueError`` on
    any structural failure. Call :func:`verify_space_join_request_pop` for the
    signature and TTL.

    Bounds ``origin``/``label`` (the two fields an approving human reads) but
    stays I/O-free, so it does NOT check that ``origin`` resolves to anything
    real. Homoglyph/IDNA-confusable detection is out of scope.
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
    label = parsed.get("label")
    if label is not None and not isinstance(label, str):
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
    if label is not None:
        _assert_bounded_safe_text(label, "label", MAX_LABEL_LENGTH)
    _assert_valid_origin_url(parsed["origin"])

    request: SpaceJoinRequestPayload = dict(parsed)  # type: ignore[assignment]
    return request


def verify_space_join_request_pop(request: SpaceJoinRequestPayload, code: str) -> None:
    """Verify ``popSig`` binds this request's keys to ``code``, and enforce the TTL.

    Split from :func:`parse_space_join_request` because ``code`` is the slot
    ADDRESS: only a caller that knows which code it pulled can check the binding.

    Raises:
        ValueError: invalid PoP signature, expired request, or a request claiming
            to stay valid longer than :data:`MAX_REQUEST_TTL_SEC` from now.
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
    # Fail closed: a garbage expiresAt is rejected, not read as "not expired".
    if expires_at_ms is None or expires_at_ms <= now_ms:
        raise ValueError("space join request: expired")

    # Anchored to THIS call's wall clock, never to the request's own createdAt:
    # neither field is covered by popSig, so an attacker controlling both could
    # keep their DIFFERENCE inside the cap while placing them a year out.
    if expires_at_ms - now_ms > MAX_REQUEST_TTL_SEC * 1000:
        raise ValueError("space join request: expiry window exceeds the maximum this package allows")


# ── Rendezvous transport ──────────────────────────────────────────────────────


def _client_for(rendezvous: Rendezvous, override: Optional["StarfishClient"]) -> "StarfishClient":
    """The anonymous client for a rendezvous, or an injected one (the test seam;
    the TS twin overrides ``fetch`` instead)."""
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

    An unwritten document does not necessarily 404: depending on the deployment
    it pulls as the STRING ``"null"``, a raw ``None``, or an empty ``{}``.
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

    Not derived from :func:`_pull_slot`, which collapses an existing-but-empty
    ``{}`` doc to ``None`` and discards its real hash. CASing ``None`` against a
    slot that HAS a hash would make clearing an already-cleared slot always fail.
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
    """Defaults to :data:`~starfish_spaces.layout.default_space_layout`. The
    request half is resolvable session-lessly."""
    client: Optional[Any] = None
    """Injected :class:`StarfishClient` (tests / custom transports)."""


@dataclass
class SpaceJoinRequestSession:
    """A requester's own end of a device-code space join.

    Carries its own ``rendezvous`` and ``layout`` so :func:`fetch_space_join_grant`
    / :func:`await_space_join_grant` take the session directly. There is
    deliberately no ``session_id``: ``code`` is the sole identifier.
    """

    request: SpaceJoinRequestPayload
    device: dict[str, str]
    code: str
    rendezvous: Rendezvous
    layout: SpaceLayout = field(default=default_space_layout)
    client: Optional[Any] = None

    # This session's OWN hash from its last successful publish. Starts None so
    # the first publish() is create-only rather than silently adopting whatever
    # occupies the slot; later publishes reuse it rather than re-pulling, so a
    # hostile overwrite between two publishes is a loud conflict.
    _last_hash: Optional[str] = field(default=None, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    async def publish(self) -> None:
        """Publish (or re-publish) the request document to the rendezvous.

        Raises:
            SpaceJoinConflictError: the slot changed since this session's last
                write. Treat the code as compromised, do not retry past it.
        """
        # Serializes overlapping publish() calls on the SAME session: without it
        # both read the same _last_hash before either awaits, and the second
        # write conflicts for a reason indistinguishable from real tampering.
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
    """Requester side, step 1: create a join request session.

    The first :meth:`SpaceJoinRequestSession.publish` is create-only CAS, so only
    the first write to a fresh code's slot succeeds.

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
    """Pass as :attr:`PublishSpaceJoinGrantOptions.base_hash`. The grant is a
    CAS UPDATE of this very document, not a fresh create."""


async def fetch_space_join_request_by_code(
    opts: FetchSpaceJoinRequestOptions,
) -> Optional[FetchedSpaceJoinRequest]:
    """Approver side, step 1: look up a request by the code the human typed.

    ``None`` means nothing to approve (nothing published, or the slot already
    advanced to ``phase="grant"``). A request that IS present but expired or
    tampered with raises, so the caller can tell "wrong code" from "expired".

    Raises:
        ValueError: the slot holds a phase-``request`` document that is
            malformed, expired, or not correctly signed for this code.
    """
    layout = opts.layout or default_space_layout
    client = _client_for(opts.rendezvous, opts.client)
    doc = await _pull_slot(client, layout.join_session_pull(opts.code))
    if doc is None:
        return None
    # Matched to the TypeScript twin: an already-approved slot is "nothing to
    # approve", not an error.
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
    """The slot address AND the seal's AAD, so a grant sealed under one code
    cannot be replayed at another code's slot."""
    space_id: str
    cap: Any
    """The member cap minted for the requester's ephemeral identity, e.g.
    ``json.loads(await invite_to_space(...))["cap"]``. Sealed, never in clear."""
    sealer: Mapping[str, str]
    """The approver's ``{edPriv, edPub}``. Its ``edPub`` becomes the grant's
    verified ``sealed_by``, which the requester TOFU-pins."""
    rendezvous: Rendezvous
    """The approver's OWN trusted server config, never a value carried inside
    the request document: that rides in a doc anyone can publish, so trusting it
    would let a malicious requester aim this device's write at a host of its
    choosing. (Hence :class:`SpaceJoinRequestPayload` has no ``rendezvous``.)"""
    base_hash: str
    """:attr:`FetchedSpaceJoinRequest.hash`. REQUIRED: the grant is a CAS UPDATE
    of the existing request document, never a create."""
    layout: Optional[SpaceLayout] = None
    client: Optional[Any] = None


async def publish_space_join_grant(opts: PublishSpaceJoinGrantOptions) -> Optional[str]:
    """Approver side, step 2: seal the minted cap and CAS-UPDATE the slot from
    ``phase="request"`` to ``phase="grant"``.

    Returns:
        The resulting hash. A caller that republishes later must pass THIS hash
        back rather than re-deriving what is currently at the slot, since an
        attacker's overwrite looks exactly like that too.

    Raises:
        ValueError: ``base_hash`` is missing.
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

    The ONE place blind-overwrite-and-retry is correct: unpairing must succeed
    even without a remembered hash (in-memory state lost across a restart), and
    "did someone else overwrite this" is meaningless when the intent is "nothing
    should be published here".

    Does not recall a grant already fetched; it only stops the CODE resolving to
    a usable grant. Real revocation is
    :func:`~starfish_spaces.members.revoke_space_access`.
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
    """An unsealed grant. Domain object: snake_case, unlike the camelCase wire."""

    space_id: str
    cap: Any
    """A real ``space:member`` cap for the requester's ephemeral device."""
    sealed_by: str
    """The Ed25519 pubkey that ACTUALLY sealed this grant, verified via the wrap
    entry's signature (never merely claimed). A trust-on-first-use pin: pass it
    back as ``expected_sealer`` on later polls so a later writer cannot silently
    replace an established pairing's grant. Nothing pins WHO this key belongs to
    on the first read; that trust comes from the human code/origin exchange."""


@dataclass
class FetchSpaceJoinGrantOptions:
    """Arguments for :func:`fetch_space_join_grant`."""

    expected_sealer: Optional[str] = None
    """TOFU pin. See :attr:`SpaceJoinGrant.sealed_by`."""


async def fetch_space_join_grant(
    session: SpaceJoinRequestSession,
    opts: Optional[FetchSpaceJoinGrantOptions] = None,
) -> Optional[SpaceJoinGrant]:
    """Requester side: read and unseal whatever grant is published at the slot.

    ``None`` while the slot is empty or still ``phase="request"``: a polling
    caller treats that as "keep waiting". A slot that IS a grant but fails to
    unseal raises instead: a real integrity signal, not a wait state.

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

    # Matched to the TypeScript twin: anything not yet a grant is a wait state.
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
    """Capped exponential backoff in seconds: ``min(1 · 2**attempt, 5)``, matching
    the TypeScript twin so both sides load the rendezvous identically."""
    return min(POLL_MIN_SEC * 2**attempt, POLL_MAX_SEC)


async def await_space_join_grant(
    session: SpaceJoinRequestSession,
    opts: Optional[AwaitSpaceJoinGrantOptions] = None,
) -> SpaceJoinGrant:
    """Requester side: poll until the approver publishes a grant, or time out.

    A transient fetch failure is retried on the next tick like a ``None``, and
    only the deadline ends the wait. The exception is :class:`ValueError`, which
    is what every integrity failure raises: those reraise immediately, since
    retrying just re-reads the same bad document.
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
        except Exception as exc:  # noqa: BLE001, retried until the deadline
            last_err = exc
        if time.monotonic() >= deadline:
            # Chained to the last error when there was one: more informative
            # than a bare timeout.
            timed_out = TimeoutError("timed out waiting for the space join to be approved")
            if last_err is None:
                raise timed_out
            raise timed_out from last_err
        await asyncio.sleep(delay_for(attempt))
        attempt += 1


# ── Bridge to the existing invite flow ────────────────────────────────────────


async def join_request_from_space_join_request(
    request: SpaceJoinRequestPayload,
    user_id_from_ed_pub: Optional[Callable[[str], Coroutine[Any, Any, str]]] = None,
) -> str:
    """Rebuild the join-request JSON :func:`~starfish_spaces.members.invite_to_space` expects.

    Sibling of :func:`~starfish_spaces.members.make_join_request`, but built from
    an already-validated request's public fields instead of a
    :class:`~starfish_spaces.session.Session` the requester has no wallet for.
    Pass the app's own ``user_id_from_ed_pub`` hook when it configured one, so
    the derived userId matches what the roster will contain.
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
    # types
    "Rendezvous",
    "SpaceJoinRequestPayload",
    "SpaceJoinGrantDoc",
    "SpaceJoinConflictError",
    "CreatedSpaceJoinRequest",
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
