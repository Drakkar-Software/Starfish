"""Typed shape of the message published to the queue after a successful push."""

from typing import Any, Required, TypedDict


class QueueMessage(TypedDict, total=False):
    """Message published to the queue after a successful document push.

    Required fields (always present):
        collection: Collection name.
        hash:       SHA-256 hex hash of the stored document.
        timestamp:  Milliseconds since epoch when the push completed.

    Optional fields (present only when the corresponding QueueConfig flag is set):
        params: Resolved URL path parameters — present when ``include_params=True``.
        body:   Push request data field — present when ``include_body=True``
                (JSON collections only). Contains the document as sent by the client,
                before server-side sanitization.
    """

    collection: Required[str]
    hash: Required[str]
    timestamp: Required[int]
    params: dict[str, str]
    body: dict[str, Any]
