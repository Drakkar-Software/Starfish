"""Pull operation for the Starfish sync protocol."""


import json
import logging
import time

from starfish_protocol.constants import AUTHOR_PUBKEY_FIELD, AUTHOR_SIGNATURE_FIELD
from starfish_server.storage.base import AbstractObjectStore, StoreContext
from starfish_server.protocol.types import StoredDocument, PullResult


async def pull(
    store: AbstractObjectStore,
    document_key: str,
    context: StoreContext | None = None,
) -> PullResult:
    """Pull the current document.

    Always returns the full stored document — ``?checkpoint=`` incremental
    filtering was removed for regular collections and is now an appendOnly-only
    concept (see :func:`handle_append_only_pull`). The returned ``timestamp`` is
    the pull time, used by the client only as a high-water mark.
    """
    timestamp = time.time_ns() // 1_000_000
    raw = await store.get_string(document_key, context=context)

    if not raw:
        return PullResult(data={}, hash="", timestamp=timestamp)

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        logging.getLogger(__name__).error(
            "Corrupt stored document at key %r: %s", document_key, exc
        )
        return PullResult(data={}, hash="", timestamp=timestamp)

    return PullResult(
        data=parsed.get("data", {}),
        hash=parsed.get("hash", ""),
        timestamp=timestamp,
        author_pubkey=parsed.get(AUTHOR_PUBKEY_FIELD),
        author_signature=parsed.get(AUTHOR_SIGNATURE_FIELD),
    )
