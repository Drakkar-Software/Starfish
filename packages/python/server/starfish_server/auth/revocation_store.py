"""Cap-cert revocation list storage.

Mirror of ``packages/ts/server/src/auth/revocation-store.ts``. See that
file for the protocol-level rationale (signed lists, monotonic
``generation`` counter, linear scan on lookup).
"""

from __future__ import annotations

import base64
from typing import Literal, Protocol, TypedDict

try:
    from typing import NotRequired
except ImportError:  # pragma: no cover - safety net for older runtimes
    from typing_extensions import NotRequired  # type: ignore[assignment]

from starfish_protocol.revocation import revocation_list_canonical_signing_input
from starfish_protocol.suites import Alg, get_suite


class RevocationEntry(TypedDict):
    """A single revoked cap-cert (identified by subject and nonce).

    ``exp`` is the cap's NATURAL expiry, not the safe pruning time: the
    resolver honors a cap until ``exp + clock_skew_sec``, so a
    persistence/compaction layer that drops the entry at ``exp`` would
    un-revoke a cap the resolver still accepts for up to the skew window. Use
    :func:`revocation_retain_until_sec` for the earliest safe prune time.
    """

    sub: str
    nonce: str
    exp: int


class RevokedSubject(TypedDict):
    """A subject-level revocation: invalidates EVERY cap with this ``sub`` for
    the issuer, regardless of nonce — the incident-response primitive for a
    compromised device or member, where re-minting under a fresh nonce would
    slip past a per-nonce :class:`RevocationEntry`. ``exp`` is the prune-after
    time the issuer sets: no earlier than the natural expiry of the
    latest-issued cap for this subject. Mirrors the TS ``RevokedSubject``.
    """

    sub: str
    exp: int


# Clock-skew slop (seconds) the resolver applies when accepting caps — it
# honors a cap until ``cert.exp + clock_skew_sec``. Mirrors ``verify_cap_cert``'s
# default ``clock_skew_sec``; a revocation entry must outlive the cap by this.
REVOCATION_RETAIN_SKEW_SEC = 300


def revocation_retain_until_sec(
    entry: RevocationEntry | RevokedSubject, skew_sec: int = REVOCATION_RETAIN_SKEW_SEC
) -> int:
    """Earliest unix-second a revocation entry may be safely pruned.

    Returns ``entry["exp"] + skew_sec``. Persistence and compaction layers MUST
    NOT drop an entry before this, otherwise a revoked-but-not-yet-expired cap
    is honored again during the skew window. The in-memory store here never
    prunes by time (it keeps each issuer's full list until a higher generation
    replaces it), so this helper exists for durable backends that do.
    """
    return entry["exp"] + skew_sec


class RevocationList(TypedDict):
    """A signed revocation list issued by a root identity."""

    v: Literal[1]
    # Issuer's crypto suite (governs the list signature). Optional; absent ⇒ ed25519.
    alg: NotRequired[Alg]
    iss: str
    issUserId: str
    generation: int
    revoked: list[RevocationEntry]
    # Subject-level revocations: every cap with one of these ``sub``s (any
    # nonce) is revoked. Optional and omitted by default, so lists predating
    # this field canonicalize and verify exactly as before.
    revokedSubjects: NotRequired[list[RevokedSubject]]
    sig: str


class _AcceptOk(TypedDict):
    ok: Literal[True]


class _AcceptErr(TypedDict):
    ok: Literal[False]
    reason: str


class RevocationStore(Protocol):
    """Pluggable contract for a revocation-list backend."""

    def is_revoked(self, iss: str, cap_sub: str, cap_nonce: str) -> bool:
        """Return ``True`` iff the cap appears in the current list for ``iss``."""
        ...

    def accept_list(
        self, list_signed: RevocationList
    ) -> _AcceptOk | _AcceptErr:
        """Upsert *list_signed*. Verifies the signature with ``list.iss`` and
        rejects lists whose generation is not strictly greater than the
        currently stored list."""
        ...


def _verify_list_signature(list_signed: RevocationList) -> bool:
    try:
        # Use the protocol's canonical function (single source of truth) so the
        # domain-separation tag and sig-stripping stay in lockstep with signing.
        canonical = revocation_list_canonical_signing_input(dict(list_signed)).encode("utf-8")
        sig_bytes = base64.b64decode(list_signed["sig"])
        # Dispatch on the issuer's suite (``alg``), defaulting to ed25519 when absent.
        return get_suite(list_signed.get("alg")).verify(
            sig_bytes, canonical, list_signed["iss"]
        )
    except Exception:
        # Fail closed on ANY error, matching the TS bare-catch. The CryptoSuite
        # `verify` contract is "never raises", so if a future suite violates it
        # the list is rejected rather than leaking a 500 + traceback.
        return False


DEFAULT_MAX_ISSUERS = 10_000


class _InMemoryRevocationStore:
    """In-memory revocation store with O(1) lookup and a max-issuers cap.

    Per-issuer ``Set[str]`` of ``"<sub>|<nonce>"`` keys is rebuilt on every
    accepted list so ``is_revoked()`` runs in O(1) regardless of list size.
    Existing issuers can always update; new issuers beyond ``max_issuers``
    are rejected with ``too-many-issuers``.
    """

    def __init__(self, max_issuers: int = DEFAULT_MAX_ISSUERS) -> None:
        self._by_issuer: dict[str, RevocationList] = {}
        self._index_by_issuer: dict[str, set[str]] = {}
        # Per-issuer set of subject-wide revoked ``sub``s (any nonce).
        self._subjects_by_issuer: dict[str, set[str]] = {}
        self._max_issuers = max_issuers

    def is_revoked(self, iss: str, cap_sub: str, cap_nonce: str) -> bool:
        # An empty ``cap_sub`` is the audience-cap sentinel (those caps bind no
        # single subject and are revoked per-nonce). It must NEVER match the
        # subject-wide set, or a stray ``revokedSubjects: [{"sub": ""}]`` would
        # blanket-revoke every audience cap from that issuer at once. Subject-wide
        # revocation applies to device/member caps, which always carry a
        # non-empty ``sub``.
        if cap_sub != "":
            subjects = self._subjects_by_issuer.get(iss)
            if subjects is not None and cap_sub in subjects:
                return True
        idx = self._index_by_issuer.get(iss)
        if idx is None:
            return False
        return f"{cap_sub}|{cap_nonce}" in idx

    def accept_list(
        self, list_signed: RevocationList
    ) -> _AcceptOk | _AcceptErr:
        if not _verify_list_signature(list_signed):
            return {"ok": False, "reason": "bad-signature"}
        iss = list_signed["iss"]
        current = self._by_issuer.get(iss)
        if current is not None and list_signed["generation"] <= current["generation"]:
            return {"ok": False, "reason": "stale-generation"}
        if current is None and len(self._by_issuer) >= self._max_issuers:
            return {"ok": False, "reason": "too-many-issuers"}
        self._by_issuer[iss] = list_signed
        self._index_by_issuer[iss] = {
            f"{entry['sub']}|{entry['nonce']}" for entry in list_signed["revoked"]
        }
        self._subjects_by_issuer[iss] = {
            s["sub"] for s in list_signed.get("revokedSubjects", [])
        }
        return {"ok": True}


def create_in_memory_revocation_store(
    *, max_issuers: int = DEFAULT_MAX_ISSUERS
) -> RevocationStore:
    """Build an in-memory revocation store.

    ``max_issuers`` caps how many distinct issuers may be tracked; new issuers
    beyond the cap are rejected with ``too-many-issuers``. Default 10 000.
    """
    return _InMemoryRevocationStore(max_issuers=max_issuers)


__all__ = [
    "REVOCATION_RETAIN_SKEW_SEC",
    "RevocationEntry",
    "RevocationList",
    "RevocationStore",
    "RevokedSubject",
    "create_in_memory_revocation_store",
    "revocation_retain_until_sec",
]
