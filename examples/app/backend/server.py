"""Starfish chat demo — backend.

A single FastAPI app that wires six Starfish extensions into the smallest
end-to-end chat server:

    • identities  — `identities_server_plugin` validates `device` cap-certs
    • sharing     — `sharing_server_plugin` validates `member` cap-certs
    • entitlements— the CLIENT reads its own feature slugs with `pullEntitlements`
                    and unlocks paid features locally. Entitlements are NOT used
                    as collection read/write roles — the server only stores the
                    per-user slug document at `users/{identity}/entitlements`.
    • keyring     — client-side only; the server just stores the opaque
                    keyring/ciphertext documents
    • audit       — `CallbackAuditLogger` records every push (see GET /audit)
    • queuing     — `create_queuing_server_plugin` + a `CustomQueue` that fans
                    message events out to SSE subscribers (GET /events)

Rooms are keyed by id (`chat/rooms/<id>`), so the app supports many rooms; a
member/device cap is scoped to a single room. The cap-resolver synthesizes
`cap:<op>:<collection>` roles from a cap's scope; a RoleEnricher then adds the
membership roles `chat:owner` / `chat:member` (see below):

    • READ  a room  → `cap:read:chat`   (any chat cap scoped to that room path)
    • WRITE a room  → `chat:owner` OR `chat:member` — membership-bound (Level 3):
      the room owner, or a write-capable member LISTED in the room's directory.
      A read-only cap omits the `write` op (no `cap:write:chat`), so it earns
      neither role and gets a 403 on send; a self-signed stranger not in the
      roster is likewise refused, so it cannot clobber an established room.

Profiles (`user/<id>/profile`) hold each user's pseudo: READ is public (everyone
sees pseudos); WRITE is restricted to the user's MAIN device via the synthesized
`device:root` role — only a self-signed root device cap (iss === sub) earns it,
so paired / one-way-provisioned devices and members get a 403 on a profile edit
even with a full `cap:write:*` scope, while reads stay public. The `{identity}`
path binding still limits each root to its OWN profile.

Run:
    uv run uvicorn server:app --reload --port 8000
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from collections import deque
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from starfish_server import (
    CollectionConfig,
    CollectionRateLimitConfig,
    FilesystemObjectStore,
    FilesystemStorageOptions,
    RateLimitConfig,
    SyncConfig,
    create_cap_cert_role_resolver,
    create_in_memory_nonce_cache,
    create_in_memory_revocation_store,
    save_config,
)
from starfish_server.router import SyncRouterOptions, create_sync_router
from starfish_audit import AuditEntry, CallbackAuditLogger
from starfish_queuing import CustomQueue, QueueConfig, create_queuing_server_plugin
from starfish_identities import identities_server_plugin
from starfish_sharing import sharing_server_plugin

FRONTEND_ORIGIN = "http://localhost:5173"

# Comma-separated allowed browser origins (default: local Vite dev server).
# Example production: STARFISH_CORS_ORIGIN=https://chat.example.com
_cors_raw = os.environ.get("STARFISH_CORS_ORIGIN", FRONTEND_ORIGIN)
CORS_ORIGINS = [o.strip() for o in _cors_raw.split(",") if o.strip()]

# Optional per-collection rate limit on `chatkeyring` to blunt TOFU room-id squat spam.
# Left off by default so the in-process test harness can rotate keyrings freely.
_keyring_rate_limit = (
    CollectionRateLimitConfig(window_ms=60_000, max_requests=30)
    if os.environ.get("STARFISH_ENABLE_KEYRING_RATE_LIMIT", "").lower() in ("1", "true", "yes")
    else None
)

# ── Storage ──────────────────────────────────────────────────────────────────
# Filesystem store — survives restarts and is shared by every tab. The data dir
# is overridable via STARFISH_DATA_DIR so tests can point at an isolated tmp dir.
store = FilesystemObjectStore(
    FilesystemStorageOptions(base_dir=os.environ.get("STARFISH_DATA_DIR", "./data"))
)


# ── Collections ───────────────────────────────────────────────────────────────
# Multiple rooms keyed by `{roomId}`. A room's keyring and member directory live
# in their OWN top-level namespaces (not under `chat/rooms/<id>`) for two reasons:
#   1. FilesystemObjectStore maps a key to a file, so `chat/rooms/<id>` cannot be
#      both a document AND the parent directory of `chat/rooms/<id>/_keyring`.
#   2. The member-cap shape rules only forbid `chat/_keyring` / `chat/_members`,
#      so keeping the keyring at `chatkeyring/rooms/<id>/_keyring` lets a
#      read/write member cap grant a direct read of it (needed to decrypt)
#      without tripping the `member-keyring-not-denied` guard.
# All keyring/member collections reuse the `chat` role names so a member cap
# scoped to the `chat` collection can reach them.
config = SyncConfig(
    version=1,
    collections=[
        # The encrypted chat document for a room. READ needs `cap:read:chat`.
        # WRITE is membership-bound (Level 3): the synthesized `chat:owner` OR
        # `chat:member` role, granted by `owner_role_enricher` only to the room's
        # owner or a writer listed in the room's member directory who also holds the
        # chat write capability. A self-signed stranger (or any cap not in the
        # roster) therefore cannot clobber an established room's document, while
        # read-only members — who lack `cap:write:chat` — still cannot post.
        CollectionConfig(
            name="chat",
            storage_path="chat/rooms/{roomId}",
            read_roles=["cap:read:chat"],
            write_roles=["chat:owner", "chat:member"],
            encryption="delegated",
            max_body_bytes=262_144,
        ),
        # Plaintext multi-recipient keyring (wrapped CEKs) for a room. Readable by
        # any holder of a `chat` cap so they can build a decryptor. WRITE is
        # OWNER-ONLY: the `chat:owner` role is synthesized by `owner_role_enricher`
        # only for the room's owner (the keyring's genesis adder) — so neither a
        # member (who can read it to decrypt) nor a self-signed stranger can
        # overwrite/rotate it, even though both hold `cap:write:chat`.
        CollectionConfig(
            name="chatkeyring",
            storage_path="chatkeyring/rooms/{roomId}/_keyring",
            read_roles=["cap:read:chat"],
            write_roles=["chat:owner"],
            encryption="none",
            max_body_bytes=65_536,
            rate_limit=_keyring_rate_limit,
        ),
        # Owner-managed member directory for a room (signed member cap-certs).
        # WRITE is OWNER-ONLY via `chat:owner` (same enricher) so the roster cannot
        # be wiped or forged by members/strangers; READ stays `cap:read:chat`.
        CollectionConfig(
            name="chatmembers",
            storage_path="chatmembers/rooms/{roomId}/_members",
            read_roles=["cap:read:chat"],
            write_roles=["chat:owner"],
            encryption="none",
            max_body_bytes=131_072,
        ),
        # Public profile holding a user's pseudo. READ is public (everyone can see
        # other users' pseudos); WRITE is restricted to the user's MAIN device via
        # the synthesized `device:root` role — only a self-signed root device cap
        # (iss === sub) earns it, so paired / one-way-provisioned devices and
        # members get 403 on a profile edit even with a full `cap:write:*` scope.
        # (We can't use the `rootOnly` collection flag here: it forbids a public
        # read role, which would hide pseudos from everyone else. `device:root` in
        # writeRoles gives the same root-device-only write while keeping reads
        # public.) The `{identity}` path binding still limits each root to its OWN
        # profile.
        CollectionConfig(
            name="profile",
            storage_path="user/{identity}/profile",
            read_roles=["public"],
            write_roles=["device:root"],
            encryption="none",
            max_body_bytes=4_096,
        ),
        # Per-user feature-slug document. The CLIENT reads its own slugs with
        # `pullEntitlements` to unlock paid features locally — entitlements are
        # NOT used as collection read/write roles. Written server-side by the
        # /demo grant endpoints (stand-in for a billing webhook).
        #
        # WRITE is gated by `billing:webhook`, a role that NO client cap (and no
        # role-enricher) ever synthesizes — so a user cannot self-grant paid slugs
        # by writing their own entitlements doc through a cap, even though their
        # account scope nominally covers the path. The trusted webhook
        # (`_set_entitlement`) writes straight to the store, bypassing role checks.
        CollectionConfig(
            name="entitlements",
            storage_path="users/{identity}/entitlements",
            read_roles=["cap:read:entitlements"],
            write_roles=["billing:webhook"],
            encryption="none",
            max_body_bytes=4_096,
        ),
        # Per-user device directory (audit/UI metadata): one entry per `device`
        # cap the root has issued, written via `addDeviceEntry`. The `{identity}`
        # binding scopes each user to their OWN `_devices` document, so a cap can
        # only list/manage the devices of its own account.
        CollectionConfig(
            name="devices",
            storage_path="users/{identity}/_devices",
            read_roles=["cap:read:devices"],
            write_roles=["cap:write:devices"],
            encryption="none",
            max_body_bytes=131_072,
        ),
        # Anonymous, ephemeral rendezvous slot for QR-in / auto-return device
        # pairing: the new device (e.g. a laptop with no camera) shows a QR, the
        # root device (phone) scans it and PUSHES the assembled PairingBundle
        # here, and the new device — which has NO cap-cert yet, so it cannot read
        # the owner-only `_devices` doc — FETCHES it from this public slot and
        # installs it. READ + WRITE are `public` because the new device is
        # credential-less and the responding root is not known to the collection
        # ahead of time; this is safe because the bundle's CEKs are E2E-wrapped to
        # the new device's KEM key and `install_pairing_bundle` verifies the root
        # signature + sub/subKem + qrNonce (+ expected_root_ed_pub). A short
        # `ttl_ms` makes the slot self-expiring; the new device also overwrites it
        # with `{}` (one-shot) after a successful install. The `{rendezvousId}`
        # path param is the hex of the QR's `qrNonce` (16 random bytes), so the
        # slot is unguessable. A tight per-collection `rate_limit` bounds the
        # overwrite-race / grind surface on the public slot: a legit pairing pushes
        # the bundle once (and clears it once), so 30 writes/min per source is
        # generous for real use while capping a flood. The limiter keys anonymous
        # writes by client IP, so this is a per-source bound (a documented
        # availability mitigation, not a fix — the slot stays public by design).
        CollectionConfig(
            name="pairingrendezvous",
            storage_path="_pairing/{rendezvousId}",
            read_roles=["public"],
            write_roles=["public"],
            encryption="none",
            ttl_ms=300_000,
            max_body_bytes=8_192,
            rate_limit=CollectionRateLimitConfig(window_ms=60_000, max_requests=30),
        ),
    ],
    # A global rate-limit config is required to enable any per-collection limit
    # (the per-collection entry above opts the rendezvous slot in). Only collections
    # that set their own `rate_limit` are limited, so the busy `chat` collection is
    # unaffected. `chatkeyring` rate limiting is opt-in via
    # `STARFISH_ENABLE_KEYRING_RATE_LIMIT=1` (recommended in production).
    rate_limit=RateLimitConfig(window_ms=60_000, max_requests=1000),
)


# ── Owner-binding: the `chat:owner` role ─────────────────────────────────────
# The chat/keyring/members collections are authorized purely by cap SCOPE — the
# resolver never checks "is the caller the room owner / a room member". On its own
# that lets any member (or any self-signed stranger holding a chat-scoped cap)
# overwrite a room's keyring, wipe its member directory, OR clobber the room
# document. We close all three with a RoleEnricher that synthesizes:
#
#   • `chat:owner`  — for the room's owner. Governs keyring + member-directory
#     writes (owner-only) and also satisfies the room-doc write role.
#   • `chat:member` — for a writer LISTED in the room's member directory who also
#     holds `cap:write:chat`. Governs room-doc writes only (Level 3). Gating on the
#     write capability preserves the read-only-member distinction: a read-only
#     member is in the directory but synthesizes no `cap:write:chat`, so it gets no
#     `chat:member` and still cannot post.
#
# Ownership is trust-on-first-use: the owner is whoever created the room's keyring
# (the genesis adder of epoch 1). A `device` cap resolves its identity to the
# issuer (root), so every one of the owner's devices qualifies; a `member` cap
# resolves to the subject. While the keyring does not exist yet the room is being
# created, so the first writer is allowed (and becomes the owner once it lands).
OWNER_ROLE = "chat:owner"
MEMBER_ROLE = "chat:member"
WRITE_CHAT_ROLE = "cap:write:chat"


def _owner_user_id_from_keyring(raw: str) -> str | None:
    """Derive the room owner's userId from the keyring's genesis adder (epoch 1)."""
    try:
        doc = json.loads(raw)
        data = doc.get("data") if isinstance(doc, dict) else None
        genesis = (data or {}).get("epochs", {}).get("1", {}).get("wrappedKeys", [])
        added_by = genesis[0]["addedBy"]
        return hashlib.sha256(bytes.fromhex(added_by)).hexdigest()[:32]
    except (json.JSONDecodeError, KeyError, IndexError, ValueError, TypeError):
        return None


def _member_user_ids_from_directory(raw: str) -> set[str]:
    """Collect the `subUserId`s listed in a room's member-directory document."""
    try:
        doc = json.loads(raw)
        data = doc.get("data") if isinstance(doc, dict) else None
        entries = (data or {}).get("entries", [])
        return {e["subUserId"] for e in entries if isinstance(e, dict) and e.get("subUserId")}
    except (json.JSONDecodeError, KeyError, TypeError, AttributeError):
        return set()


def make_owner_role_enricher(object_store):
    """Return a RoleEnricher granting `OWNER_ROLE` / `MEMBER_ROLE` for a room.

    Reads the room's keyring (to resolve the owner) and, for a non-owner write-capable
    caller, its member directory (to resolve membership). Both reads are fresh — same
    as the existing owner read — so a just-revoked/just-removed member is reflected
    immediately; a production deployment SHOULD add a short TTL cache keyed by roomId.
    """

    async def owner_role_enricher(auth, params):
        room_id = params.get("roomId")
        if not room_id:
            return []
        # `chat:owner` / `chat:member` only ever gate WRITES, so they are meaningful
        # only for a write-capable caller. Gating on `cap:write:chat` preserves the
        # read-only distinction everywhere: a read-only device (even one of the OWNER's
        # own devices) or a read-only member synthesizes no `cap:write:chat`, so it
        # earns neither role and cannot write the room / keyring / roster.
        if WRITE_CHAT_ROLE not in auth.roles:
            return []
        try:
            raw = await object_store.get_string(f"chatkeyring/rooms/{room_id}/_keyring")
        except Exception:  # noqa: BLE001 — store error ⇒ treat as "no keyring"
            raw = None
        # No keyring yet (or an unparseable one): TOFU — the first writer becomes the
        # owner. An unparseable keyring is treated as "unowned" so a stranger who wins
        # the create race with a GARBAGE keyring cannot permanently brick the room
        # (recoverable-DoS, not hardening).
        owner = _owner_user_id_from_keyring(raw) if raw else None
        if not raw or owner is None or owner == auth.identity:
            return [OWNER_ROLE]

        # Not the owner: grant `chat:member` to a caller LISTED in the room's member
        # directory (Level-3 room-doc binding). A stranger (not in the roster) gets
        # nothing, so it cannot clobber an established room's document.
        try:
            members_raw = await object_store.get_string(f"chatmembers/rooms/{room_id}/_members")
        except Exception:  # noqa: BLE001 — store error ⇒ no roster ⇒ no membership
            members_raw = None
        if members_raw and auth.identity in _member_user_ids_from_directory(members_raw):
            return [MEMBER_ROLE]
        return []

    return owner_role_enricher


# ── Auth: cap-cert role resolver ────────────────────────────────────────────────
nonce_cache = create_in_memory_nonce_cache(window_ms=5 * 60_000, max_entries=100_000)
revocation_store = create_in_memory_revocation_store()

role_resolver = create_cap_cert_role_resolver(
    nonce_cache=nonce_cache,
    revocation_store=revocation_store,
    allow_anonymous=True,
    # The resolver's pre-auth body guard defaults to 64 KB; raise it to the
    # largest per-collection ceiling (chat = 256 KB) so a legitimately-sized
    # encrypted room write is not rejected before the per-collection check runs.
    max_body_bytes=262_144,
    # Register validators for the `device` and `member` cap kinds. Without
    # these, strict-kind dispatch rejects every minted cap-cert.
    plugins=[identities_server_plugin, sharing_server_plugin],
)


# ── Audit ──────────────────────────────────────────────────────────────────────
# In-memory ring buffer for the demo's `/audit` panel. The bound is raised well
# above the original 100 so an actor cannot trivially bury an earlier action by
# generating a handful of later writes. It is still in-memory and bounded — a
# production deployment MUST stream audit events to a persistent, append-only sink
# (the `CallbackAuditLogger` makes that a one-line swap).
AUDIT_LOG_MAXLEN = 10_000
audit_log: deque[dict] = deque(maxlen=AUDIT_LOG_MAXLEN)


async def _audit_record(entry: AuditEntry) -> None:
    record = {
        "action": entry.action,
        "collection": entry.collection,
        "identity": entry.identity or "anonymous",
        "success": entry.success,
        "statusCode": entry.status_code,
        "ts": int(time.time() * 1000),
    }
    audit_log.append(record)
    print(
        f"[AUDIT] {record['action']} {record['collection']} "
        f"by {record['identity']} -> {record['statusCode']}"
    )


# ── Queuing → Server-Sent Events ───────────────────────────────────────────────
# Every successful push to the `chat` collection is published to the queue; the
# CustomQueue callback fans the event out to all connected SSE clients, which
# turns the poll-based sync into a live feed.
sse_subscribers: set[asyncio.Queue[str]] = set()


async def _broadcast(subject: str, payload: bytes) -> None:
    message = payload.decode("utf-8") if isinstance(payload, (bytes, bytearray)) else str(payload)
    for queue in list(sse_subscribers):
        try:
            queue.put_nowait(message)
        except asyncio.QueueFull:  # pragma: no cover - slow consumer, drop
            pass


message_queue = CustomQueue(on_publish=_broadcast)
queuing_plugin = create_queuing_server_plugin(
    queue=message_queue,
    # Only the `chat` collection publishes — keyring/member writes stay quiet.
    # include_params surfaces {roomId} so SSE clients can filter to their room.
    collections={"chat": QueueConfig(topic="chat", include_params=True)},
)


# ── Sync router ─────────────────────────────────────────────────────────────────
sync_router = create_sync_router(
    SyncRouterOptions(
        store=store,
        config=config,
        role_resolver=role_resolver,
        role_enricher=make_owner_role_enricher(store),
        audit_logger=CallbackAuditLogger(_audit_record),
        plugins=[queuing_plugin],
    )
)


# ── App + demo-only helper endpoints ────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await save_config(store, config)
    yield


app = FastAPI(title="Starfish chat demo", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],  # Authorization + X-Starfish-{Sig,Ts,Nonce,Pub} + X-Demo-Secret
)


async def _set_entitlement(user_id: str, features: list[str]) -> None:
    """Write a user's feature-slug document directly to the store.

    Stand-in for a billing webhook: in production this document is written by a
    trusted system. The client reads it back with `pullEntitlements`, which
    reads `data.features`.
    """
    doc = {"v": 1, "data": {"features": features}, "timestamps": {}, "hash": ""}
    await store.put(f"users/{user_id}/entitlements", json.dumps(doc))


# DEMO ONLY: the grant/revoke/audit endpoints stand in for real admin + billing-
# webhook auth. They are gated behind a shared secret (`X-Demo-Secret` header) and
# are SECURE BY DEFAULT — when `STARFISH_DEMO_SECRET` is unset they are disabled
# (403), so a deployment can't accidentally ship them open. A real app replaces
# grant/revoke with an authenticated billing webhook and puts `/audit` behind an
# admin cap.
_DEMO_SECRET = os.environ.get("STARFISH_DEMO_SECRET")


def _check_demo_secret(request: Request) -> JSONResponse | None:
    """Return an error response if the demo secret is missing/disabled, else None."""
    if not _DEMO_SECRET:
        return JSONResponse(
            {"error": "demo admin endpoints disabled; set STARFISH_DEMO_SECRET"}, status_code=403
        )
    if request.headers.get("x-demo-secret") != _DEMO_SECRET:
        return JSONResponse({"error": "missing or invalid X-Demo-Secret"}, status_code=401)
    return None


@app.post("/demo/grant")
async def demo_grant(request: Request) -> JSONResponse:
    """Grant the `premium` slug to a user (simulated purchase). Requires X-Demo-Secret."""
    denied = _check_demo_secret(request)
    if denied is not None:
        return denied
    body = await request.json()
    user_id = body.get("userId")
    if not user_id:
        return JSONResponse({"error": "userId required"}, status_code=400)
    await _set_entitlement(user_id, ["premium"])
    return JSONResponse({"ok": True, "features": ["premium"]})


@app.post("/demo/revoke")
async def demo_revoke(request: Request) -> JSONResponse:
    """Revoke all paid slugs from a user. Requires X-Demo-Secret."""
    denied = _check_demo_secret(request)
    if denied is not None:
        return denied
    body = await request.json()
    user_id = body.get("userId")
    if not user_id:
        return JSONResponse({"error": "userId required"}, status_code=400)
    await _set_entitlement(user_id, [])
    return JSONResponse({"ok": True, "features": []})


@app.post("/revocations")
async def post_revocation(request: Request) -> JSONResponse:
    """Accept a signed `RevocationList` and hand it to the revocation store.

    The list is self-authenticating — it carries the issuer's Ed25519 signature
    and a monotonic generation counter — so no cap is needed to submit it; the
    store verifies the signature and rejects stale generations. Once accepted,
    the cap-resolver returns 401 for every (sub, nonce) named in the list.
    """
    body = await request.json()
    result = revocation_store.accept_list(body)
    if not result.get("ok"):
        return JSONResponse(result, status_code=400)
    return JSONResponse(result)


@app.get("/audit")
async def get_audit(request: Request) -> JSONResponse:
    """Admin audit panel. Requires X-Demo-Secret (it discloses identities + actions)."""
    denied = _check_demo_secret(request)
    if denied is not None:
        return denied
    return JSONResponse(list(audit_log))


@app.get("/events")
async def events() -> StreamingResponse:
    """SSE stream of chat-change events fed by the queuing plugin.

    Unauthenticated by design in this demo: payloads are metadata-only
    (collection, hash, timestamp, params.roomId) — never document bodies.
    Production deployments that cannot leak activity metadata SHOULD gate this
    route (cap-auth, room-scoped token, or network ACL) and/or filter server-side.
    """
    queue: asyncio.Queue[str] = asyncio.Queue(maxsize=64)
    sse_subscribers.add(queue)

    async def event_stream():
        try:
            yield ": connected\n\n"
            while True:
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {message}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"  # keep the connection open
        finally:
            sse_subscribers.discard(queue)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# Mount at the root (no prefix): the cap-cert request signature and scope-path
# matching are computed against the path the client signs, which is relative to
# its `baseUrl`. Keeping the sync routes at `/pull|/push|/list` (where the
# resolver strips the action prefix) avoids a path mismatch.
app.include_router(sync_router)
