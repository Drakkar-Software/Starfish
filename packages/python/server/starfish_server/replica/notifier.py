"""Notification publisher — fan-out push notifications to replica subscribers."""


import hashlib
import hmac
import json
import logging

import httpx

from starfish_server.replica.subscriber import SubscriptionStore

logger = logging.getLogger(__name__)

_SIGNATURE_HEADER = "X-Starfish-Signature"


def _sign(payload: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_signature(body: bytes, signature_header: str, secret: str) -> bool:
    expected = _sign(body, secret)
    return hmac.compare_digest(expected, signature_header)


class NotificationPublisher:
    """Fan-out push notifications to registered replica subscribers.

    Called fire-and-forget after each successful write on the primary.
    Failed deliveries are logged; the replica catches up on its next scheduled pull.
    """

    def __init__(
        self,
        subscription_store: SubscriptionStore,
        *,
        client: httpx.AsyncClient | None = None,
        webhook_secret: str | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._store = subscription_store
        self._owned_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._secret = webhook_secret

    async def close(self) -> None:
        """Close the underlying HTTP client if it was created internally."""
        if self._owned_client:
            await self._client.aclose()

    async def notify(self, collection_name: str, new_hash: str, timestamp: int) -> None:
        subscribers = await self._store.list_for_collection(collection_name)
        if not subscribers:
            return

        payload: dict[str, str | int] = {
            "collection": collection_name,
            "hash": new_hash,
            "timestamp": timestamp,
        }
        body = json.dumps(payload).encode()

        headers = {"Content-Type": "application/json"}
        if self._secret:
            headers[_SIGNATURE_HEADER] = _sign(body, self._secret)

        for sub in subscribers:
            try:
                resp = await self._client.post(
                    f"{sub.webhook_url.rstrip('/')}/replica/notify",
                    content=body,
                    headers=headers,
                )
                if not resp.is_success:
                    logger.warning(
                        "Notification to %s returned HTTP %s",
                        sub.webhook_url,
                        resp.status_code,
                    )
            except httpx.HTTPError as exc:
                logger.warning("Failed to notify %s: %s", sub.webhook_url, exc)
