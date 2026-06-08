"""Per-collection queue configuration (owned by the queuing plugin)."""

from __future__ import annotations

import re
from dataclasses import dataclass

# Default charset a ``subject_param`` value must FULLY match before it is appended
# to the publish subject. Tighter than a URL path param: it admits only
# ``[a-zA-Z0-9_-]`` so the derived subject can never carry a broker metacharacter
# (NATS ``.`` ``*`` ``>``) or a token a downstream subject sanitizer would fold
# into a colliding value. Apps override per collection via
# :attr:`QueueConfig.subject_id_pattern`.
DEFAULT_SAFE_ID = re.compile(r"^[a-zA-Z0-9_-]+$")


@dataclass
class QueueConfig:
    """Per-collection queue publishing configuration.

    Apps pass a ``{collection_name: QueueConfig}`` map to
    :func:`create_queuing_server_plugin`. Collections absent from that map
    publish nothing.
    """

    topic: str | None = None
    """Subject/topic to publish to. Defaults to the collection name."""

    subject_param: str | None = None
    """Route path-param whose value is appended to the subject as a trailing
    token, yielding a per-resource subject ``<topic>.<value>`` (e.g.
    ``posts.changed.<postId>``).

    This lets a consumer/broker filter by resource (e.g. a NATS
    ``<topic>.>`` subscription) without parsing the message body. The value is
    read straight from :attr:`WriteEvent.params`, so it works **independently of**
    ``include_params`` — the suffix is derived even when the params are not
    forwarded in the message.

    The value MUST fully match :attr:`subject_id_pattern`; when it is missing,
    non-string, or contains anything outside that charset, the base subject is
    published **unsuffixed**. This re-validation is deliberate defense-in-depth:
    even when an upstream role/route gate has already constrained the id, the
    queuing layer must never emit a broker subject containing ``.`` ``*`` ``>``
    from an id that slipped through gate drift."""

    subject_id_pattern: "re.Pattern[str]" = DEFAULT_SAFE_ID
    """Compiled regex the :attr:`subject_param` value must ``fullmatch`` to be
    appended. Defaults to :data:`DEFAULT_SAFE_ID` (``^[a-zA-Z0-9_-]+$``). Pass a
    pinned local literal if you want the gate to stay fixed regardless of future
    library changes to the default."""

    include_params: bool = False
    """Include the resolved route path parameters in the published message."""

    include_body: bool = False
    """Include the pushed ``data`` object in the message (JSON collections only)."""

    include_identity: bool = False
    """Include the authenticated writer's identity (``WriteEvent.identity``) as
    ``identity`` in the published message. Default ``False`` (off). Forwarding
    this exposes *who* wrote each document to the queue/broker — metadata the
    server otherwise never emits — so it is strictly per-collection opt-in."""
