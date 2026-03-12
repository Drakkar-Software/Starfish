"""Pull operation for the Starfish sync protocol."""


import json

from starfish_server.interfaces import IObjectStore
from starfish_server.timestamp import next_timestamp
from starfish_server.protocol.types import StoredDocument, PullResult
from starfish_server.protocol.timestamps import filter_by_checkpoint


async def pull(
    store: IObjectStore,
    document_key: str,
    checkpoint: int = 0,
) -> PullResult:
    """Pull the current document, optionally filtered by checkpoint.

    - No checkpoint (or 0): returns full data
    - With checkpoint: returns only paths updated after checkpoint
    - hash is always the hash of the FULL document
    """
    timestamp = next_timestamp()
    raw = await store.get_string(document_key)

    if not raw:
        return PullResult(data={}, hash="", timestamp=timestamp)

    parsed = json.loads(raw)
    doc = StoredDocument(
        v=parsed["v"],
        data=parsed["data"],
        timestamps=parsed["timestamps"],
        hash=parsed["hash"],
        author_pubkey=parsed.get("authorPubkey"),
        author_signature=parsed.get("authorSignature"),
    )

    if checkpoint and checkpoint > 0 and doc.timestamps:
        filtered = filter_by_checkpoint(doc.data, doc.timestamps, checkpoint)
        return PullResult(
            data=filtered,
            hash=doc.hash,
            timestamp=timestamp,
            author_pubkey=doc.author_pubkey,
            author_signature=doc.author_signature,
        )

    return PullResult(
        data=doc.data,
        hash=doc.hash,
        timestamp=timestamp,
        author_pubkey=doc.author_pubkey,
        author_signature=doc.author_signature,
    )
