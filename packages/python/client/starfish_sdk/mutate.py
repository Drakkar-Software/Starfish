"""Read-modify-write a document with hash-CAS conflict retry.

The everyday way to atomically edit a synced document: pull the current version,
apply a pure ``mutator`` to its data, push the result with the read hash, and
retry on a :class:`ConflictError` (a concurrent writer moved the hash) by
re-reading FRESH server state and re-applying the mutator. A missing document
(404) is surfaced to the mutator as ``DocState(data=None, hash=None)`` so it can
create the doc on first write.

This replaces the ad-hoc ``for attempt in …: pull; mutate; try push except
ConflictError`` loop that applications otherwise hand-roll around every editable
doc. The ``mutator`` MUST be idempotent — it re-runs on each retry — and returns
``None`` to signal a no-op (nothing changed; skip the write).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from starfish_sdk.types import ConflictError, StarfishHttpError


@dataclass
class DocState:
    """The current state handed to a mutator: the document data (or ``None`` when
    the doc does not exist yet) and the hash to base the next push on."""

    data: Optional[dict[str, Any]]
    hash: Optional[str]


# Pure transform from the current document to the next. Return the full next
# document body to write, or ``None`` for a no-op (the write is skipped). Runs
# once per attempt on freshly-pulled state, so it must be idempotent.
DocMutator = Callable[[DocState], Optional[dict[str, Any]]]


async def mutate_doc(
    client: Any,
    path: str,
    mutator: DocMutator,
    *,
    max_attempts: int = 3,
) -> Optional[dict[str, Any]]:
    """Atomically read-modify-write the document at ``path``.

    Returns the document that was written, or ``None`` if the mutator signalled a
    no-op. Raises the underlying error on a non-conflict failure, or a
    :class:`ConflictError` if every attempt raced and lost.
    """
    attempts = max(1, max_attempts)
    for attempt in range(attempts):
        data: Optional[dict[str, Any]] = None
        base_hash: Optional[str] = None
        try:
            res = await client.pull(path)
            data = res.data
            # Keep the server hash verbatim (only a missing hash → None), mirroring the
            # TS helper's `res.hash ?? null` so an empty-string hash isn't coerced away.
            base_hash = res.hash if res.hash is not None else None
        except StarfishHttpError as err:
            # A 404 means the doc does not exist yet — hand the mutator a null
            # state so it can create it. Any other HTTP error propagates.
            if err.status != 404:
                raise

        next_doc = mutator(DocState(data=data, hash=base_hash))
        if next_doc is None:
            return None
        try:
            await client.push(path, next_doc, base_hash)
            return next_doc
        except ConflictError:
            if attempt < attempts - 1:
                continue
            raise
    # Unreachable: the final attempt either returns or re-raises above.
    raise ConflictError()
