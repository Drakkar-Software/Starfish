"""Build and publish a queue message from a :class:`WriteEvent`."""

from __future__ import annotations

import json
import logging

from starfish_protocol.plugins import WriteEvent

from starfish_queuing.base import AbstractQueue
from starfish_queuing.config import QueueConfig
from starfish_queuing.message import QueueMessage

logger = logging.getLogger(__name__)


async def publish_change_event(
    queue: AbstractQueue,
    config: QueueConfig,
    event: WriteEvent,
) -> None:
    """Publish a change event for *event* using *config*.

    Errors are logged but never propagate — a queue outage must not break
    client writes.
    """
    try:
        subject = config.topic or event.collection
        if config.subject_param:
            # Per-resource subject: append ``.<id>`` read straight from the route
            # params (independent of include_params). Re-validate the id against
            # the configured charset — NEVER emit a subject carrying a broker
            # metacharacter from an id that slipped through an upstream gate drift.
            raw_id = (event.params or {}).get(config.subject_param)
            if isinstance(raw_id, str) and config.subject_id_pattern.fullmatch(raw_id):
                subject = f"{subject}.{raw_id}"
        msg: QueueMessage = {
            "collection": event.collection,
            "hash": event.hash,
            "timestamp": event.timestamp,
        }
        if config.include_params and event.params:
            msg["params"] = dict(event.params)
        if config.include_body:
            if event.body is not None:
                msg["body"] = dict(event.body)
            else:
                logger.warning(
                    "include_body enabled for %s but request data is not a plain "
                    "object; body omitted from queue message",
                    event.collection,
                )
        if config.include_identity and event.identity:
            msg["identity"] = event.identity
        await queue.publish(subject, json.dumps(msg).encode())
    except Exception:
        logger.warning(
            "Failed to publish queue event for %s", event.collection, exc_info=True,
        )
