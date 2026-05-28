"""Stateful cursor for incremental pulling of append-only collections.

The Python mirror of ``packages/ts/client/src/append-log.ts``. See that module
and ``docs/ts/server/append-only-collections.md`` for the full design.
"""

from __future__ import annotations

import asyncio
from typing import Any, Literal, TypedDict, cast

from starfish_protocol.append_author import verify_append_author
from starfish_protocol.crypto import Encryptor
from starfish_sdk.client import StarfishClient

# The ``/pull/`` action prefix; mirrors ``PUSH_PATH_PREFIX`` for the read side.
PULL_PATH_PREFIX = "/pull/"

# What to do when a single element fails verification or decryption during a
# pull (or ``get_decrypted_items``):
#   - "throw" (default): the pull is atomic — the first bad element raises and NO
#     state is mutated, so the checkpoint never advances past an element that
#     could not be re-fetched.
#   - "skip": a bad element is dropped from the returned/decrypted batch and the
#     checkpoint still advances past it (so it is never re-fetched). Intended for
#     tolerating decrypt failures in a multi-writer / E2EE log. SECURITY NOTE:
#     "skip" ALSO silently drops elements that fail author verification — if you
#     also need strict authorship, set ``verify_author.expected_author_pubkey``
#     or check each element's ``authorPubkey`` against your authorized set.
ElementErrorPolicy = Literal["throw", "skip"]


class AuthorVerifier(TypedDict, total=False):
    """Per-element author-signature verification policy for :class:`AppendLogCursor`."""

    # If set, every element's ``authorPubkey`` MUST equal this key (compared as
    # case-insensitive hex), else the pull fails. Omit to accept any signing key
    # (verify only that the signature is valid for the element's self-declared
    # ``authorPubkey`` — see the ``verify_author`` note on restricting authors).
    expected_author_pubkey: str


class AppendAuthorError(Exception):
    """Raised when an append element's author signature fails verification."""

    def __init__(self, ts: int) -> None:
        self.ts = ts
        super().__init__(f"append element author verification failed (ts={ts})")


def checkpoint_of(items: list[dict[str, Any]]) -> int:
    """Largest ``ts`` among ``items``, or ``0`` when empty. The checkpoint for an
    append-only log is exactly this — the server returns elements with
    ``ts > checkpoint`` and element timestamps are strictly increasing."""
    return max((it["ts"] for it in items), default=0)


def _with_author(ts: int, data: dict[str, Any], src: dict[str, Any]) -> dict[str, Any]:
    """Copy the optional author fields from ``src`` onto a fresh element with ``data``."""
    out: dict[str, Any] = {"ts": ts, "data": data}
    if "authorPubkey" in src:
        out["authorPubkey"] = src["authorPubkey"]
    if "authorSignature" in src:
        out["authorSignature"] = src["authorSignature"]
    return out


class AppendLogCursor:
    """A stateful cursor over an append-only collection.

    It owns the accumulated array of elements and pulls only what is new: each
    :meth:`pull` derives the checkpoint from the last element it holds and asks
    the server for elements with a greater ``ts``. The incremental, stateful
    counterpart to the stateless ``client.pull(path, append_field=..., since=...)``,
    and the sibling of :class:`SyncManager` for append-only logs (a log only grows,
    so there is no merge / push-conflict machinery). The cursor accumulates every
    pulled element in memory; for an unboundedly large log, pull a bounded window
    with raw ``client.pull(path, last=...)`` instead.

    Cold start (nothing persisted) — first ``pull()`` fetches the whole collection::

        log = AppendLogCursor(client, "/pull/events")
        all_items = await log.pull()

    Warm start (resume from persisted data) — first ``pull()`` fetches only newer
    elements; persistence is a round-trip of ``items``::

        log = AppendLogCursor(client, "/pull/events", initial_items=store.load())
        fresh = await log.pull()
        store.save(log.items)

    Warm start for an **E2EE** log — persist ciphertext, render decrypted::

        log = AppendLogCursor(client, "/pull/streamchat", encryptor=enc,
                              persist_encrypted=True, on_element_error="skip",
                              initial_items=store.load())     # ciphertext from disk
        history = log.get_decrypted_items()                   # render persisted history
        fresh = await log.pull()                              # decrypted delta
        store.save(log.items)                                 # ciphertext back to disk

    Each stored/returned element is the raw envelope ``{"ts", "data",
    "authorPubkey"?, "authorSignature"?}``. When an ``encryptor`` is given (and
    ``persist_encrypted`` is off), the freshly-pulled elements carry the
    **decrypted** ``data`` (``ts``/author fields preserved); author verification,
    when enabled, runs over the original (pre-decryption) ``data``. Under
    ``persist_encrypted`` the stored elements keep their **ciphertext** ``data``
    (E2EE-safe to persist) and decryption happens only on read via :meth:`pull`
    and :meth:`get_decrypted_items`.

    Caveat (default mode, with an ``encryptor``): a returned element holds
    DECRYPTED ``data`` but an ``authorSignature`` computed over the stored
    CIPHERTEXT — they no longer match, so do NOT re-verify a decrypted element
    with ``verify_append_author``. The cursor already verified it (over the
    ciphertext) at pull time when ``verify_author`` is on; ``authorPubkey`` is
    retained for identity.

    ``verify_author`` checks each signature is valid for the element's
    self-declared ``authorPubkey`` — it does NOT by itself restrict WHICH authors
    are accepted. Set ``expected_author_pubkey`` for a single author, or check
    each ``el["authorPubkey"]`` against your own authorization source after pull
    (for a multi-writer log, the authorized set lives there and changes over
    time, not here). The signature covers ``data`` + the document key but NOT
    ``ts``: a malicious server cannot forge content, but can reorder/re-timestamp
    authentic elements, so trust ``ts`` only as far as you trust the server.
    """

    def __init__(
        self,
        client: StarfishClient,
        pull_path: str,
        *,
        append_field: str = "items",
        initial_items: list[dict[str, Any]] | None = None,
        since: int | None = None,
        encryptor: Encryptor | None = None,
        on_element_error: ElementErrorPolicy = "throw",
        persist_encrypted: bool = False,
        verify_author: bool | AuthorVerifier = False,
    ) -> None:
        seed = list(initial_items) if initial_items else []
        seed_checkpoint = checkpoint_of(seed)
        if since is not None:
            if since < 0:
                raise ValueError("since must be non-negative")
            if since < seed_checkpoint:
                raise ValueError("since must be >= the max ts of initial_items")
            checkpoint = since
        else:
            checkpoint = seed_checkpoint

        self._client = client
        self._pull_path = pull_path
        self._append_field = append_field
        self._encryptor = encryptor
        self._on_element_error: ElementErrorPolicy = on_element_error
        self._persist_encrypted = persist_encrypted
        self._verify_author = verify_author
        self._document_key = pull_path.removeprefix(PULL_PATH_PREFIX)
        self._items: list[dict[str, Any]] = seed
        self._last_checkpoint: int = checkpoint
        # Serializes overlapping pull() calls so each runs against the checkpoint
        # the previous one advanced — no two fetch and double-append the same window.
        self._pull_lock = asyncio.Lock()

    async def pull(self) -> list[dict[str, Any]]:
        """Fetch elements newer than the current checkpoint, verify + decrypt them,
        append them to the local log, and return ONLY the newly-fetched batch
        (decrypted when an ``encryptor`` is set).

        Atomic under ``on_element_error="throw"`` (the default): the batch is fully
        verified and decrypted into a local before any state mutation, so a
        verify/decrypt failure raises without advancing the checkpoint past
        elements that could never be re-fetched. Under ``"skip"`` a failing element
        is dropped from the returned batch but the checkpoint still advances past it.

        Safe to call concurrently: overlapping calls are serialized internally, so
        each runs against the checkpoint the previous one advanced (no double-fetch
        of the same window).
        """
        async with self._pull_lock:
            return await self._do_pull()

    async def _do_pull(self) -> list[dict[str, Any]]:
        since = self._last_checkpoint
        # Omit ``since`` on cold start so the request carries no ``?checkpoint=``.
        raw = await self._client.pull(
            self._pull_path,
            append_field=self._append_field,
            since=since if since > 0 else None,
        )
        elements = cast("list[dict[str, Any]]", raw)

        batch: list[dict[str, Any]] = []  # decrypted, returned to the caller
        stored: list[dict[str, Any]] = []  # what we keep in ``_items`` (cipher- or plaintext)
        max_ts = since
        for el in elements:
            ts = el["ts"]
            # Defensive: guard a misbehaving/mocked server from making us
            # double-append a held element. Gated on ``since > 0`` to mirror the
            # server (which only filters when checkpoint > 0): on a cold start
            # ``since`` is 0 and we must NOT drop a legitimate ``ts == 0`` first element.
            if since > 0 and ts <= since:
                continue
            # Advance past every windowed element BEFORE verify/decrypt so a skipped
            # element still moves the checkpoint and is never re-fetched.
            if ts > max_ts:
                max_ts = ts

            decrypted: dict[str, Any] | None = None
            try:
                self._verify_one(el)
                data = self._encryptor.decrypt(el["data"]) if self._encryptor is not None else el["data"]
                decrypted = _with_author(ts, data, el)
            except Exception:
                # "throw" re-raises here, before any state mutation below — atomic.
                if self._on_element_error != "skip":
                    raise

            if self._persist_encrypted:
                # Keep the original ciphertext envelope (even for a skipped element:
                # it is valid data we simply cannot read now — a later key might).
                stored.append(_with_author(ts, el["data"], el))
            elif decrypted is not None:
                stored.append(decrypted)
            if decrypted is not None:
                batch.append(decrypted)

        self._items.extend(stored)
        self._last_checkpoint = max_ts
        return batch

    def _verify_one(self, el: dict[str, Any]) -> None:
        """Verify one element's author signature over its RAW (pre-decryption)
        ``data``. Raises :class:`AppendAuthorError` on any failure. No-op when
        verification is disabled."""
        v = self._verify_author
        if not v:
            return
        expected: str | None = None
        if isinstance(v, dict):
            expected = v.get("expected_author_pubkey")
        pub = el.get("authorPubkey")
        sig = el.get("authorSignature")
        if not pub or not sig:
            raise AppendAuthorError(el["ts"])
        if expected is not None and pub.lower() != expected.lower():
            raise AppendAuthorError(el["ts"])
        if not verify_append_author(self._document_key, el["data"], pub, sig):
            raise AppendAuthorError(el["ts"])

    @property
    def items(self) -> list[dict[str, Any]]:
        """The full accumulated log (a shallow copy), in ``ts`` order. Under
        ``persist_encrypted`` these carry CIPHERTEXT ``data`` (persist them as-is,
        then re-seed via ``initial_items``); otherwise decrypted/plaintext data."""
        return list(self._items)

    def get_decrypted_items(self) -> list[dict[str, Any]]:
        """The full accumulated log, DECRYPTED — for rendering warm-started history
        in ``persist_encrypted`` mode (where :attr:`items` holds ciphertext). Honors
        ``on_element_error`` (a ``"skip"`` cursor drops elements it cannot read).
        When the cursor has no ``encryptor``, or is not in ``persist_encrypted``
        mode, the held elements are already plaintext/decrypted and returned as-is."""
        snapshot = list(self._items)
        if self._encryptor is None or not self._persist_encrypted:
            return snapshot
        out: list[dict[str, Any]] = []
        for el in snapshot:
            try:
                self._verify_one(el)
                data = self._encryptor.decrypt(el["data"])
                out.append(_with_author(el["ts"], data, el))
            except Exception:
                if self._on_element_error != "skip":
                    raise
        return out

    @property
    def checkpoint(self) -> int:
        """The current checkpoint: the max ``ts`` held (the next pull's ``since``).
        ``0`` when nothing has been pulled or seeded."""
        return self._last_checkpoint

    def set_checkpoint(self, ts: int) -> None:
        """Restore the checkpoint without seeding items — for persistence layers
        that store only the checkpoint. Resumes incrementally across restarts.
        Rejects a value below the max ``ts`` already held: rewinding would make
        the next pull re-deliver, and duplicate, elements the cursor already has."""
        if ts < checkpoint_of(self._items):
            raise ValueError("checkpoint must be >= the max ts already held")
        self._last_checkpoint = ts
