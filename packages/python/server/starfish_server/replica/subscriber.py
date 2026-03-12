"""Subscription store — persists the list of replica webhook subscribers."""


import json
from dataclasses import asdict, dataclass

from starfish_server.interfaces import IObjectStore
from starfish_server.router.helpers import validate_url_not_private

_SUBSCRIPTIONS_KEY = "__sync__/subscriptions.json"


@dataclass
class Subscription:
    webhook_url: str
    collections: list[str]
    subscribed_at: int


class SubscriptionStore:
    """Persists replica webhook subscriptions in the shared object store.

    The subscription list is stored as ``__sync__/subscriptions.json``.
    All mutating operations reload-then-save to avoid races; for production
    deployments behind multiple processes, use a distributed lock or a
    dedicated database instead.
    """

    def __init__(self, store: IObjectStore) -> None:
        self._store = store

    async def _load(self) -> list[Subscription]:
        raw = await self._store.get_string(_SUBSCRIPTIONS_KEY)
        if not raw:
            return []
        records = json.loads(raw)
        return [Subscription(**r) for r in records]

    async def _save(self, subs: list[Subscription]) -> None:
        await self._store.put(
            _SUBSCRIPTIONS_KEY,
            json.dumps([asdict(s) for s in subs], indent=2),
            content_type="application/json",
        )

    async def add(self, webhook_url: str, collections: list[str], subscribed_at: int) -> None:
        """Register or update a subscriber. Replaces any existing entry for the same URL."""
        if not validate_url_not_private(webhook_url):
            raise ValueError(f"Webhook URL is not allowed: {webhook_url!r}")
        subs = await self._load()
        subs = [s for s in subs if s.webhook_url != webhook_url]
        subs.append(Subscription(webhook_url=webhook_url, collections=collections, subscribed_at=subscribed_at))
        await self._save(subs)

    async def remove(self, webhook_url: str) -> None:
        """Remove a subscriber by URL. No-op if not found."""
        subs = await self._load()
        subs = [s for s in subs if s.webhook_url != webhook_url]
        await self._save(subs)

    async def list_for_collection(self, collection_name: str) -> list[Subscription]:
        """Return all subscribers interested in a given collection."""
        subs = await self._load()
        return [s for s in subs if collection_name in s.collections]

    async def list_all(self) -> list[Subscription]:
        """Return all registered subscribers."""
        return await self._load()
