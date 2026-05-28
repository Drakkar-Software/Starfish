"""Cap-cert role resolver — Python mirror of cap-resolver.ts.

Builds a ``RoleResolver`` that authenticates a request by parsing
``Authorization: Cap <base64-cert>`` plus the ``X-Starfish-{Sig,Ts,Nonce}``
triplet, then synthesizes a role set from the cap-cert's scope.

This is opt-in: pass the returned resolver as
``SyncRouterOptions.role_resolver`` to enable v3 cap-cert auth.
"""

from __future__ import annotations

import base64
import json
import re
import time
from typing import TYPE_CHECKING, Any

import httpx

from starfish_protocol.cap import (
    is_root_device_cap,
    path_glob_match,
    user_id_from_pub_hex,
    verify_cap_cert,
)
from starfish_protocol.request_signing import (
    RequestSignature,
    is_within_clock_skew,
    verify_request_signature,
)
from starfish_protocol.constants import (
    HEADER_AUTHORIZATION,
    HEADER_SIG,
    HEADER_TS,
    HEADER_NONCE,
    HEADER_PUB,
)
from starfish_server.auth.nonce_cache import NonceCache
from starfish_server.auth.revocation_store import RevocationStore
from starfish_server.constants import IDENTITY_KEY, ROLE_PUBLIC, ROLE_ROOT_DEVICE
from starfish_server.plugins import (
    CapCertValidator,
    ServerPlugin,
    compose_plugin_validators,
    default_server_plugin,
)

if TYPE_CHECKING:
    from starfish_server.router.route_builder import AuthResult, RoleResolver


# Header names sourced from the shared protocol constants (single source with the
# client, which sends them) — ``_get_header`` matches case-insensitively, so the
# canonical-case names resolve against Starlette's lowercased headers.
#   HEADER_PUB conveys the presenter's Ed25519 pubkey for an ``audience`` cap
#     (which binds no single subject); the per-request signature is verified
#     against it and, when the cap carries an ``aud`` allow-list, membership is
#     checked. Ignored for device/member caps, whose verifying key is ``cert["sub"]``.
_HEADER_AUTH = HEADER_AUTHORIZATION
_HEADER_SIG = HEADER_SIG
_HEADER_TS = HEADER_TS
_HEADER_NONCE = HEADER_NONCE
_HEADER_PUB = HEADER_PUB
_HEADER_CONTENT_LENGTH = "content-length"

# A presenter Ed25519 pubkey: 64-char lowercase hex (32-byte). ASCII class
# ``[0-9a-f]`` (not ``\w``) so the predicate matches the TS ``/^[0-9a-f]{64}$/``
# exactly.
_PUB_HEX_RE = re.compile(r"[0-9a-f]{64}")

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_DEFAULT_MAX_BODY_BYTES = 64 * 1024
_DEFAULT_MAX_CAP_HEADER_BYTES = 8 * 1024

# A header that must be a base-10 integer. Validated explicitly (rather than
# leaning on ``int()``'s leniency) so TypeScript and Python accept exactly the
# same strings: ``int()`` strips surrounding whitespace and accepts ``+``/``_``
# separators (and Unicode digits!), while JS ``Number()`` accepts ``0x10`` /
# ``1e3`` / ``12.5``. The shared rule must use the ASCII class ``[0-9]`` — NOT
# ``\d``, which is Unicode-aware in Python (matches Arabic-Indic etc.) but
# ASCII-only in JS, so ``\d`` would let a Unicode-digit ``Ts`` authenticate on
# Python while TS rejected it. ``[0-9]`` rejects all of those on both sides.
_INTEGER_HEADER_RE = re.compile(r"-?[0-9]+")


def _parse_integer_header(value: str) -> int | None:
    """Return the integer value of ``value`` or ``None`` when it is not a
    base-10 integer string under the shared cross-language rule."""
    if _INTEGER_HEADER_RE.fullmatch(value) is None:
        return None
    return int(value)


class CapAuthError(Exception):
    """Resolver-side error surfacing a desired HTTP status to the caller."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def _parse_cap_header(value: str) -> dict | None:
    if not value.startswith("Cap "):
        return None
    b64 = value[len("Cap "):].strip()
    if not b64:
        return None
    try:
        raw = base64.b64decode(b64)
        return json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None


def _path_and_query(request: Any) -> str:
    url = request.url
    path = getattr(url, "path", "")
    query = getattr(url, "query", "")
    if query:
        return f"{path}?{query}"
    return path


def _host_from_request(request: Any) -> str:
    """Extract the host portion of the inbound request URL.

    Starlette's ``URL.netloc`` includes default ports (``:443`` for https,
    ``:80`` for http), whereas the client's signed canonical input uses
    JS-style host normalization (default ports dropped). Routing the URL
    through ``httpx.URL`` yields the same normalization, so client and
    server agree on the ``h`` field byte-for-byte.

    Returns ``""`` for an unparseable URL — the client's empty-host path
    still verifies symmetrically against ``""``.
    """
    try:
        netloc = httpx.URL(str(request.url)).netloc
    except (httpx.InvalidURL, ValueError):
        return ""
    if isinstance(netloc, bytes):
        return netloc.decode("ascii")
    return netloc


def _get_header(request: Any, name: str) -> str | None:
    headers = request.headers
    # Starlette Headers is case-insensitive; raw dicts may not be.
    if hasattr(headers, "get"):
        v = headers.get(name)
        if v is None:
            v = headers.get(name.lower())
        if v is None:
            v = headers.get(name.title())
        return v
    return None


def _synthesize_roles(cert: dict) -> list[str]:
    roles: set[str] = set()
    scope = cert["scope"]
    for op in scope["ops"]:
        for col in scope["collections"]:
            roles.add(f"cap:{op}:{col}")
    if cert["kind"] in ("member", "audience"):
        # Both are issuer-scoped grants: carry the issuer identity so path-owner
        # role enrichers can admit the grant against the owner's namespace.
        for col in scope["collections"]:
            roles.add(f"delegated:{cert['issUserId']}:{col}")
    # A self-signed device cap (iss == sub) is the root device; mark it so
    # `rootOnly` collections can admit it and reject every delegated cap.
    if is_root_device_cap(cert):
        roles.add(ROLE_ROOT_DEVICE)
    # ROLE_SELF is NOT emitted here — the route-builder's identity-vs-params
    # check adds it conditionally when `params.identity == auth.identity`,
    # which centralizes the rule and prevents `self` from leaking across users.
    return list(roles)


def _canonicalize_request_path(request_path: str) -> str:
    """Collapse empty and ``.`` segments so a deny cannot be evaded with a
    superstring path. ``col/_keyring/``, ``col//_keyring`` and
    ``col/./_keyring`` all canonicalize to ``col/_keyring``. (``..`` is left
    intact — it is rejected upstream by ``is_unsafe_document_key`` — and would
    not help evade a deny here in any case.)

    Unlike the TypeScript twin, this does NOT percent-decode the segments — and
    must not. ASGI delivers ``scope["path"]`` already percent-decoded (per spec),
    so ``request.url.path`` (the input here, via ``_path_and_query``) and
    ``request.path_params`` (the storage key) are both decoded once and agree.
    Decoding again here would double-decode (``%256b`` → ``%6b`` → ``k``) and
    re-open the very evasion the TS ``canonicalizeRequestPath`` decode closes,
    where ``new URL().pathname`` is NOT decoded. The two implementations diverge
    at the function level but are equivalent end-to-end; do not "restore parity"
    by adding a decode here.
    """
    return "/".join(seg for seg in request_path.split("/") if seg not in ("", "."))


def match_scope_path(request_path: str, scope_paths: list[str] | None) -> bool:
    """Glob match against ``scope.paths`` entries.

    ``**`` matches any run of characters including slashes; a single ``*``
    matches any run of non-slash characters. Entries starting with ``!`` are
    denylist rules.

    The per-glob matching is delegated to the protocol's ``path_glob_match``
    so the request-path enforcement here and the member-cap scope barriers in
    ``starfish_sharing`` share one definition of glob semantics — a divergence
    between the two would let a cap clear the mint/validation barrier yet match
    a path the resolver grants.

    The request path is canonicalized (empty/``.`` segments collapsed) before
    matching, and a deny rule ``!path`` covers both ``path`` and any descendant
    ``path/...`` — so an owner-only deny like ``!col/_keyring`` cannot be
    side-stepped with ``col/_keyring/``, ``col/_keyring/x`` or ``col/./_keyring``.

    Returns ``True`` when ``scope_paths`` is empty/None (no restriction),
    or when at least one allow rule matches AND no deny rule matches.
    """
    if not scope_paths:
        return True

    canonical = _canonicalize_request_path(request_path)
    allows: list[str] = []
    denies: list[str] = []
    for entry in scope_paths:
        if entry.startswith("!"):
            denies.append(entry[1:])
        else:
            allows.append(entry)
    if not allows:
        return False
    if not any(path_glob_match(p, canonical) for p in allows):
        return False
    # A deny covers the exact path AND any descendant (``<deny>/...``), so a
    # sibling/child read cannot slip past an owner-only deny.
    if any(
        path_glob_match(d, canonical) or path_glob_match(f"{d}/**", canonical)
        for d in denies
    ):
        return False
    return True


def _strip_action_prefix(path_and_query: str) -> str:
    """Strip the action prefix (``/pull/``, ``/push/``, ``/list/``) and an
    optional namespace segment from a request path, returning the storage-path
    form that ``scope.paths`` globs match against. Drops the query string.

    Examples:

    - ``/pull/notes/abc?x=1`` → ``notes/abc``
    - ``/push/users/123/data`` → ``users/123/data``
    - ``/myns/pull/shared/abc`` → ``shared/abc``
    - ``/list/shared`` → ``shared``
    - ``/foo/bar`` (no recognised action) → ``foo/bar`` (best-effort)
    """
    q_idx = path_and_query.find("?")
    path_only = path_and_query[:q_idx] if q_idx >= 0 else path_and_query
    trimmed = path_only[1:] if path_only.startswith("/") else path_only
    segs = trimmed.split("/")
    for i, s in enumerate(segs):
        if s in ("pull", "push", "list"):
            return "/".join(segs[i + 1:])
    return trimmed


def _is_batch_pull_path(path_and_query: str) -> bool:
    """True for the batch-pull routes (``/batch/pull`` and ``/<ns>/batch/pull``).

    These carry no storage path in their URL — they name collections + params in
    the query — so the per-request ``scope.paths`` check cannot run at the
    resolver; the batch handler re-checks each RESOLVED key against
    ``scope.paths`` instead. The length + action-prefix guard keeps a standalone
    pull of a collection literally named ``batch/pull`` (``/pull/batch/pull``)
    from being mistaken for the batch route.
    """
    q_idx = path_and_query.find("?")
    path_only = path_and_query[:q_idx] if q_idx >= 0 else path_and_query
    segs = [s for s in path_only.split("/") if s]
    n = len(segs)
    if n < 2 or segs[-2] != "batch" or segs[-1] != "pull":
        return False
    if n == 2:  # /batch/pull
        return True
    # /<ns>/batch/pull — a single namespace segment, never an action prefix.
    return n == 3 and segs[0] not in ("pull", "push", "list")


# ─── Private orchestrator helpers ────────────────────────────────────────────
#
# Each helper covers one concern of the resolver pipeline. They MUST preserve
# the verify ordering — cheap O(1) checks (header presence, clock skew) run
# before any Ed25519 verify burns CPU; the cap-cert verify is the most
# expensive step and lives in the orchestrator, NOT inside any helper here.


def _parse_and_validate_cap_header(
    request: Any,
    *,
    allow_anonymous: bool,
    max_cap_header_bytes: int,
) -> dict | None:
    """Parse and shape-validate the ``Authorization: Cap …`` header.

    Returns ``None`` when the header is missing/non-``Cap`` AND
    ``allow_anonymous`` is ``True`` — the orchestrator turns that into an
    ``AuthResult(identity="", roles=["public"])``. Raises
    :class:`CapAuthError` (HTTP 401) for: missing header with
    ``allow_anonymous=False``, header over the size cap, malformed
    base64/JSON, or any shape-validation failure.

    Does NOT perform the Ed25519 cap-cert verify — that is the
    orchestrator's responsibility (kept there so the verify ordering is
    observable in one place).
    """
    auth_header = _get_header(request, _HEADER_AUTH)
    if auth_header is None or not auth_header.startswith("Cap "):
        if allow_anonymous:
            return None
        raise CapAuthError(401, "missing Authorization: Cap header")
    # Bound the Authorization header BEFORE base64/JSON parsing.
    if len(auth_header) > max_cap_header_bytes:
        raise CapAuthError(401, "cap-too-large")
    cert = _parse_cap_header(auth_header)
    if cert is None:
        raise CapAuthError(401, "malformed cap-cert in Authorization header")
    return cert


def _read_sig_headers(request: Any) -> tuple[str, int, str]:
    """Read and parse the request-signature header triplet.

    Returns ``(sig, ts, nonce)`` on success. Raises :class:`CapAuthError`
    (HTTP 401) when any header is missing or ``ts`` is not an integer.
    The caller does the clock-skew check next — keeping the skew gate in
    the orchestrator makes the verify ordering visible without indirection.
    """
    sig_b64 = _get_header(request, _HEADER_SIG)
    ts_header = _get_header(request, _HEADER_TS)
    nonce_b64 = _get_header(request, _HEADER_NONCE)
    if sig_b64 is None or ts_header is None or nonce_b64 is None:
        raise CapAuthError(401, "missing request signature headers")
    ts = _parse_integer_header(ts_header)
    if ts is None:
        raise CapAuthError(401, "invalid X-Starfish-Ts")
    return sig_b64, ts, nonce_b64


async def _buffer_and_check_body(
    request: Any,
    method: str,
    max_body_bytes: int,
) -> bytes:
    """Pre-auth body-buffer DoS amplifier guard.

    Validates the ``Content-Length`` header BEFORE touching the body
    stream; only after the header passes do we read the body. For
    non-write methods the body is treated as the empty buffer regardless
    of any payload sent.

    Raises :class:`CapAuthError` (HTTP 413) for: missing
    ``Content-Length`` on a write, non-numeric/negative
    ``Content-Length``, or ``Content-Length`` greater than
    ``max_body_bytes``. The route-builder's per-collection
    ``check_body_limit`` still applies downstream.
    """
    if method not in _WRITE_METHODS:
        return b""
    content_length = _get_header(request, _HEADER_CONTENT_LENGTH)
    if content_length is None:
        raise CapAuthError(413, "missing Content-Length on write")
    parsed_cl = _parse_integer_header(content_length)
    if parsed_cl is None or parsed_cl < 0:
        raise CapAuthError(413, "invalid Content-Length")
    if parsed_cl > max_body_bytes:
        raise CapAuthError(413, "request body too large")
    try:
        return await request.body()
    except Exception:  # noqa: BLE001 — body read failures degrade to empty
        return b""


def _bind_auth_identity(cert: dict, verifying_pub_hex: str) -> str:
    """Bind ``auth.identity`` to the cap-cert kind.

    - ``device``   caps proxy for the issuer → ``issUserId``
    - ``member``   caps are scoped grants to the subject → ``subUserId``
    - ``audience`` caps bind no subject → the presenter's own userId,
      ``user_id_from_pub_hex(verifying_pub_hex)``

    This is the cryptographic root of "device of A cannot access B's data": a
    device cap's identity is always its issuer, and an audience presenter's
    identity is the hash of the key they proved possession of, so neither can
    pose as another user even if ``scope.paths`` was forged to look permissive.

    Raises :class:`CapAuthError` (HTTP 401) for a ``member`` cap missing
    ``subUserId`` and for any unrecognized kind. Strict-kind dispatch should
    already have rejected those cases upstream; this is defense in depth.
    """
    kind = cert.get("kind")
    if kind == "device":
        return cert["issUserId"]
    if kind == "member":
        sub_user_id = cert.get("subUserId")
        if not sub_user_id:
            raise CapAuthError(401, "member cap missing subUserId")
        return sub_user_id
    if kind == "audience":
        return user_id_from_pub_hex(verifying_pub_hex)
    raise CapAuthError(401, f'unsupported cap-cert kind "{kind}"')


def _resolve_verifying_pub_hex(cert: dict, pub_header: str | None) -> str:
    """Resolve the Ed25519 pubkey the per-request signature must verify against.

    - device/member → the cap's single subject ``cert["sub"]``
    - audience      → the presenter pubkey from the ``X-Starfish-Pub`` header

    For audience caps the header is mandatory (every redeemer signs as self) and
    must be 64-char lowercase hex; missing/malformed → :class:`CapAuthError`
    (HTTP 401).
    """
    if cert.get("kind") == "audience":
        if pub_header is None or _PUB_HEX_RE.fullmatch(pub_header) is None:
            raise CapAuthError(401, "missing or malformed X-Starfish-Pub for audience cap")
        return pub_header
    sub = cert.get("sub")
    if not isinstance(sub, str):
        raise CapAuthError(401, "cap-cert missing subject")
    return sub


def _read_identity_param(request: Any) -> Any:
    """Read the route's ``{identity}`` path param defensively.

    Returns ``None`` when the call site has no router context (e.g.
    ``/config``) or when ``request.path_params`` is absent.
    """
    try:
        params = getattr(request, "path_params", None)
        if params is not None and hasattr(params, "get"):
            return params.get(IDENTITY_KEY)
    except Exception:  # noqa: BLE001 — non-route call sites lack path_params
        return None
    return None


def create_cap_cert_role_resolver(
    *,
    nonce_cache: NonceCache,
    revocation_store: RevocationStore,
    allow_anonymous: bool = True,
    max_body_bytes: int = _DEFAULT_MAX_BODY_BYTES,
    max_cap_header_bytes: int = _DEFAULT_MAX_CAP_HEADER_BYTES,
    plugins: list[ServerPlugin] | None = None,
    strict_kind_dispatch: bool = True,
) -> "RoleResolver":
    """Build a ``RoleResolver`` performing cap-cert verification.

    :param nonce_cache: Replay-protection nonce cache (per-process or shared).
    :param revocation_store: Revocation list lookup.
    :param allow_anonymous: When ``True`` (default), missing/malformed
        Authorization yields ``AuthResult(identity="", roles=["public"])``.
        When ``False``, such requests raise :class:`CapAuthError` with
        status 401.
    :param max_body_bytes: Pre-auth hard upper bound on the request body
        for write methods. Writes whose ``Content-Length`` is absent or
        greater than this value are rejected with HTTP 413 BEFORE any
        body buffering. Defaults to 64 KB.
    :param max_cap_header_bytes: Hard upper bound on the
        ``Authorization: Cap <...>`` header value. Headers larger than
        this are rejected with HTTP 401 and message ``cap-too-large``
        before any base64/JSON parsing is attempted. Defaults to 8 KB.
    :param plugins: Optional list of :class:`ServerPlugin` contributing
        per-kind cap-cert validators. Validators run **after** the core
        ``verify_cap_cert`` checks (sig + window + baseline well-
        formedness) and may raise to reject a request. Strict-kind
        dispatch is **always** active (secure by default): a cap whose
        ``kind`` has no registered validator is rejected 401. When omitted,
        the built-in device-only ``default_server_plugin`` is used —
        ``device`` caps are accepted but ``member`` caps are rejected until
        a validator for them is wired. To accept member caps, pass
        ``[default_server_plugin, sharing_server_plugin]``. An explicit
        empty list (``plugins=[]``) registers no kinds → every cap is
        rejected (anonymous-only).
    :param strict_kind_dispatch: When a cap arrives whose ``kind`` is not
        registered by any plugin, reject the request with HTTP 401. Default
        ``True`` (secure). Set to ``False`` to fall through and accept
        unregistered kinds with baseline checks only — useful during a
        phased rollout, but it re-opens the member-cap bypass (member
        barriers live in ``sharing_server_plugin``), so keep it ``True`` in
        production.
    """
    # Imported lazily to keep the route_builder module ↔ cap_resolver
    # dependency one-directional.
    from starfish_server.router.route_builder import AuthResult, Presenter

    # Strict-kind dispatch is ALWAYS active (secure by default). With no
    # ``plugins``, fall back to the built-in device-only
    # ``default_server_plugin``: ``device`` caps are accepted but
    # ``member``/unknown kinds are rejected until the app wires a validator
    # (e.g. ``sharing_server_plugin``). An explicit empty list (``plugins=[]``)
    # registers no kinds → every cap is rejected (anonymous-only).
    plugin_validators: dict[str, list[CapCertValidator]] = compose_plugin_validators(
        plugins if plugins is not None else [default_server_plugin]
    )

    async def resolver(request: Any) -> "AuthResult":
        # Parse the cap-cert header (anonymous short-circuit lives here).
        cert = _parse_and_validate_cap_header(
            request,
            allow_anonymous=allow_anonymous,
            max_cap_header_bytes=max_cap_header_bytes,
        )
        if cert is None:
            return AuthResult(identity="", roles=[ROLE_PUBLIC])

        # Cheap O(1) checks BEFORE the Ed25519 cap-cert verify.
        sig_b64, ts, nonce_b64 = _read_sig_headers(request)
        now_ms = int(time.time() * 1000)
        if not is_within_clock_skew(ts, now_ms):
            raise CapAuthError(401, "request timestamp outside clock skew")

        # Ed25519 cap-cert verify — kept in the orchestrator to make the
        # verify ordering reviewable in one place.
        now_sec = now_ms // 1000
        cert_result = verify_cap_cert(cert, now=now_sec)
        if not cert_result.get("ok"):
            reason = cert_result.get("reason", "invalid")
            raise CapAuthError(401, f"cap-cert {reason}")

        # Strict-kind dispatch (secure by default). A kind with no registered
        # validator is rejected 401 (unless ``strict_kind_dispatch`` was
        # explicitly disabled for a phased rollout). Each validator runs in
        # registration order; any raise rejects the request. This is what stops
        # a forged ``member`` cap from being accepted on a resolver that has not
        # wired ``sharing_server_plugin``.
        kind = cert.get("kind", "")
        validators = plugin_validators.get(kind)
        if not validators:
            if strict_kind_dispatch:
                raise CapAuthError(
                    401,
                    f'cap-cert kind "{kind}" has no registered validator',
                )
        else:
            for validator in validators:
                try:
                    validator(cert)
                except Exception as exc:  # noqa: BLE001 — plugin contract
                    raise CapAuthError(
                        401, f"cap-cert plugin reject: {exc}"
                    ) from exc

        # Body buffer + Content-Length pre-auth guard.
        method_upper = request.method.upper()
        body_bytes = await _buffer_and_check_body(request, method_upper, max_body_bytes)

        # Binary blob uploads are signed by the client (push_blob) with an EMPTY body —
        # clients don't fold large/streamed blob bytes into the per-request signature, and
        # blob integrity comes from the content seal (AES-GCM bound to the storage path). The
        # discriminator is the content type: a JSON write (application/json) signs the real
        # body; ANY other (non-empty) media type is a blob upload signed over an empty body.
        # An empty/missing content type is treated as non-blob (sign the body) so a missing
        # header can't dodge body-signing; a JSON collection still rejects a non-JSON content
        # type at the handler's MIME check. The media type is compared on its prefix (params
        # stripped) so a crafted "application/json; x=octet-stream" can't flip the gate.
        # Mirrors the TS cap-resolver.
        media_type = (_get_header(request, "content-type") or "").split(";")[0].strip().lower()
        is_blob_upload = media_type != "" and media_type != "application/json"
        signing_body = b"" if is_blob_upload else body_bytes

        # Resolve the verifying pubkey: device/member → ``cert["sub"]``;
        # audience → the presenter pubkey from ``X-Starfish-Pub`` (mandatory).
        verifying_pub_hex = _resolve_verifying_pub_hex(
            cert, _get_header(request, _HEADER_PUB)
        )

        # Verify the per-request Ed25519 signature, bound to host.
        signature = RequestSignature(sig=sig_b64, ts=ts, nonce=nonce_b64)
        sig_ok = verify_request_signature(
            method_upper,
            _path_and_query(request),
            signing_body,
            signature,
            verifying_pub_hex,
            host=_host_from_request(request),
        )
        if not sig_ok:
            raise CapAuthError(401, "bad request signature")

        # Audience allow-list membership. Runs AFTER the signature proves the
        # presenter holds ``verifying_pub_hex``'s private key, and BEFORE the
        # nonce-cache write so a non-member never consumes a cache slot. When
        # ``aud`` is absent, any identity may redeem.
        if (
            cert.get("kind") == "audience"
            and cert.get("aud") is not None
            and verifying_pub_hex not in cert["aud"]
        ):
            raise CapAuthError(403, "presenter is not in the cap audience")

        # Replay protection — the nonce must not have been seen yet. Keyed by the
        # verifying pubkey so two audience redeemers never share a nonce namespace.
        if not nonce_cache.check_and_remember(verifying_pub_hex, nonce_b64, now_ms):
            raise CapAuthError(401, "nonce replay")

        # Revocation list lookup. An audience cap has no single subject, so it is
        # revoked by nonce alone — the issuer writes ``sub: ""``, matched by
        # passing "" here; per-cap revocation still works (the nonce is unique).
        revocation_sub = "" if cert.get("kind") == "audience" else cert.get("sub", "")
        if revocation_store.is_revoked(cert["iss"], revocation_sub, cert["nonce"]):
            raise CapAuthError(401, "cap-cert revoked")

        # Bind auth.identity to the cap-cert.
        identity = _bind_auth_identity(cert, verifying_pub_hex)

        # scope.paths glob matching (with `{identity}` substitution and
        # `!`-prefixed denylist). Strips the `/pull/`, `/push/`, `/list/`
        # action prefix so the glob matches the storage-path form.
        storage_path = _strip_action_prefix(_path_and_query(request))
        scope_paths = cert["scope"].get("paths")
        expanded_paths: list[str] | None = (
            [p.replace("{identity}", identity) for p in scope_paths]
            if scope_paths is not None
            else None
        )
        # A member/audience cap is a SCOPED grant — it must carry an explicit
        # path scope. Only a device/root cap (a proxy for the issuer's full
        # authority) may be path-unrestricted. Without this, a member/audience
        # cap minted with no ``scope.paths`` would clear the gate for every path
        # (``match_scope_path(_, None)`` is True), reaching the owner-only
        # ``_keyring``/``_members``. Defense-in-depth alongside the mint/
        # server-side shape barrier (``_assert_scope_barriers``).
        if cert["kind"] != "device" and not expanded_paths:
            raise CapAuthError(
                403, "member/audience cap must carry an explicit scope.paths"
            )
        # Batch pull carries no single storage path in its URL, so the per-request
        # path-scope check can't run here — the batch handler enforces
        # ``scope.paths`` per RESOLVED key instead. Every other verify step (sig,
        # nonce, revocation) still ran above, and ``scope_paths`` is returned below
        # for that per-key check.
        if not _is_batch_pull_path(_path_and_query(request)) and not match_scope_path(
            storage_path, expanded_paths
        ):
            raise CapAuthError(403, "request path is outside cap scope")

        # `{identity}` URL-param binding: when the route exposes an
        # ``identity`` path param, it must equal ``auth.identity``.
        param_identity = _read_identity_param(request)
        if param_identity is not None and param_identity != identity:
            raise CapAuthError(
                403, "request identity does not match cap-bound identity"
            )

        # Carry the expanded scope so the route layer can authorize sibling
        # reads (e.g. the ?withKeyring=1 ``<key>/_keyring`` shortcut) against
        # the same paths the data request was checked against. ``presenter``
        # carries the key that signed THIS request (already verified above) so
        # the append handler can bind a signed element's author to its writer.
        return AuthResult(
            identity=identity,
            roles=_synthesize_roles(cert),
            scope_paths=expanded_paths,
            presenter=Presenter(pub_hex=verifying_pub_hex),
        )

    return resolver  # type: ignore[return-value]


__all__ = ["CapAuthError", "create_cap_cert_role_resolver"]
