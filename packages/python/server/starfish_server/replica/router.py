"""FastAPI router for replica subscription and notification endpoints."""


import asyncio
import logging
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from starfish_server.config.schema import CollectionConfig
from starfish_server.replica.manager import ReplicaManager
from starfish_server.replica.notifier import verify_signature
from starfish_server.replica.subscriber import SubscriptionStore
from starfish_server.router.route_builder import AuthResult, RoleResolver

logger = logging.getLogger(__name__)

_SIGNATURE_HEADER = "X-Starfish-Signature"


def create_replica_router(
    *,
    replica_manager: ReplicaManager | None = None,
    subscription_store: SubscriptionStore | None = None,
    collections: list[CollectionConfig] | None = None,
    role_resolver: RoleResolver | None = None,
    subscribe_role: str = "admin",
) -> APIRouter:
    """Create a FastAPI ``APIRouter`` with replica coordination endpoints.

    Both endpoints are optional — only mount what you need:

    * **Primary side** — ``POST /replica/subscribe``:
      Requires ``subscription_store``, ``role_resolver``, and ``subscribe_role``.
      Replicas call this to register their webhook URL.

    * **Replica side** — ``POST /replica/notify``:
      Requires ``replica_manager`` and ``collections`` (to look up ``webhook_secret``).
      The primary calls this after each successful write.

    A single server can mount both endpoints to participate as both primary
    and replica (chained replication).

    Args:
        replica_manager: The local ``ReplicaManager`` (replica side).
        subscription_store: Persisted subscriber list (primary side).
        collections: All collection configs — used to look up ``webhook_secret`` per
            collection (replica side).
        role_resolver: Auth callback (primary side) — must return an
            :class:`~starfish_server.router.route_builder.AuthResult`.
        subscribe_role: Role required to register a subscription (default ``"admin"``).
    """
    router = APIRouter()

    if subscription_store is not None:
        async def subscribe_handler(request: Request) -> JSONResponse:
            # Auth: caller must have subscribe_role
            if role_resolver is not None:
                try:
                    auth: AuthResult = await role_resolver(request)
                except Exception:
                    return JSONResponse({"error": "Unauthorized"}, status_code=401)
                if subscribe_role not in auth.roles:
                    return JSONResponse({"error": "Forbidden"}, status_code=403)

            content_type = request.headers.get("content-type", "")
            if "application/json" not in content_type:
                return JSONResponse(
                    {"error": "Content-Type must be application/json"}, status_code=415
                )

            body = await request.json()
            if not isinstance(body, dict):
                return JSONResponse({"error": "Body must be a JSON object"}, status_code=400)

            webhook_url = body.get("webhook_url")
            col_names = body.get("collections")
            if not isinstance(webhook_url, str) or not webhook_url:
                return JSONResponse({"error": "webhook_url is required"}, status_code=400)
            if not isinstance(col_names, list) or not col_names:
                return JSONResponse({"error": "collections must be a non-empty list"}, status_code=400)
            if not all(isinstance(n, str) for n in col_names):
                return JSONResponse({"error": "collections must be a list of strings"}, status_code=400)

            await subscription_store.add(webhook_url, col_names, time.time_ns() // 1_000_000)
            logger.info("New replica subscriber: %s for %s", webhook_url, col_names)
            return JSONResponse({"ok": True})

        router.add_api_route("/replica/subscribe", subscribe_handler, methods=["POST"])

    if replica_manager is not None:
        # Build a quick lookup: collection name → webhook_secret
        _secrets: dict[str, str] = {}
        if collections:
            for col in collections:
                if col.remote and col.remote.webhook_secret:
                    _secrets[col.name] = col.remote.webhook_secret

        async def notify_handler(request: Request) -> JSONResponse:
            content_type = request.headers.get("content-type", "")
            if "application/json" not in content_type:
                return JSONResponse(
                    {"error": "Content-Type must be application/json"}, status_code=415
                )

            raw_body = await request.body()
            body_json = await request.json()
            if not isinstance(body_json, dict):
                return JSONResponse({"error": "Body must be a JSON object"}, status_code=400)

            collection_name = body_json.get("collection")
            if not isinstance(collection_name, str) or not collection_name:
                return JSONResponse({"error": "collection is required"}, status_code=400)

            # Verify HMAC signature if a secret is configured for this collection
            secret = _secrets.get(collection_name)
            if secret:
                sig_header = request.headers.get(_SIGNATURE_HEADER, "")
                if not sig_header:
                    return JSONResponse({"error": "Missing signature"}, status_code=401)
                if not verify_signature(raw_body, sig_header, secret):
                    return JSONResponse({"error": "Invalid signature"}, status_code=401)

            # Trigger sync in background — return immediately
            asyncio.create_task(replica_manager.on_notification(collection_name))
            return JSONResponse({"ok": True})

        router.add_api_route("/replica/notify", notify_handler, methods=["POST"])

    return router
