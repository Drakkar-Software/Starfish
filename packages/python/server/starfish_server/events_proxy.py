"""Authenticated SSE proxy router factory.

Generalizes the per-app ``/events`` SSE proxy (an app gating an upstream
change-event firehose behind cap-cert auth + per-resource authorization) into a
framework primitive. Apps supply the policy callbacks; this module owns the
shared mechanics:

  - authenticate the (bodyless) subscribe request → identity | None (401),
  - parse a bounded ``?<candidates_param>=a,b,c`` candidate list (400 on
    overflow),
  - per-candidate gate: open-gate a public candidate (``public_predicate``) or
    call ``authorize(identity, candidate)``; reject any candidate whose id does
    not fullmatch ``id_pattern`` on EITHER branch,
  - cap the authorized set at ``max_topics`` (silent truncation beyond),
  - map authorized candidates through ``topic_mapper`` to upstream topics,
  - FIREHOSE-PREVENTION INVARIANT: the upstream URL always carries at least one
    ``topic=``; an empty authorized set substitutes the sentinel ``__none__``,
  - proxy the upstream SSE stream, propagating client disconnect.

No app-specific (octobot/octochat/…) names appear here — the upstream topic
transform, the authorization policy, and the public open-gate are all caller
supplied.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

if TYPE_CHECKING:
    from re import Pattern

logger = logging.getLogger(__name__)

# Shared default id charset: matches the per-app product/space id rule. fullmatch
# (NOT ``match``) — Python ``re``'s ``$`` matches before a trailing ``\n``, so a
# candidate ``foo\n`` would slip through ``.match()`` and could perturb the
# upstream topic reconstruction.
DEFAULT_SAFE_ID: "Pattern[str]" = re.compile(r"^[a-zA-Z0-9_-]+$")

# Sentinel substituted when nothing is authorized, so the upstream URL always
# carries at least one ``topic=`` (a topic-less upstream subscribe would be a
# firehose).
_NONE_SENTINEL = "__none__"


def create_events_proxy_router(
    *,
    authenticate: Callable[[Request], Awaitable[str | None]],
    candidates_param: str,
    authorize: Callable[[str, str], Awaitable[bool]],
    topic_mapper: Callable[[str], list[str]],
    upstream_url: str,
    max_candidates: int,
    max_topics: int,
    public_predicate: Callable[[str], bool] | None = None,
    id_pattern: "Pattern[str]" = DEFAULT_SAFE_ID,
) -> APIRouter:
    """Build a :class:`fastapi.APIRouter` exposing a single authenticated SSE
    ``GET /events`` proxy.

    :param authenticate: Resolves the caller's identity from the (bodyless)
        request, or ``None`` → 401. Wrap
        :func:`starfish_server.router.cap_resolver.authenticate_meta_request`
        with the route's pre-bound caches/validators.
    :param candidates_param: Query-param name carrying the comma-separated
        candidate ids (e.g. ``"products"``).
    :param authorize: ``async (identity, candidate) -> bool`` — true iff the
        caller may subscribe to ``candidate``. Called once per non-public
        candidate (so keep it cheap / bounded; ``max_candidates`` bounds the
        fan-out).
    :param topic_mapper: ``candidate -> list[str]`` — the upstream topic
        transform for ONE authorized candidate (the caller owns sanitization /
        namespacing). May return multiple upstream topics per candidate.
    :param upstream_url: Upstream SSE endpoint; the ``topic=`` query is appended.
    :param max_candidates: Pre-auth cap on parsed candidate ids; 400 if
        exceeded (bounds per-request ``authorize`` calls).
    :param max_topics: Cap on AUTHORIZED candidates; beyond it, extra candidates
        are silently truncated (they won't live-update until reconnect).
    :param public_predicate: Optional ``candidate -> bool`` — when true the
        candidate is open-gated (no ``authorize`` call), still id-validated and
        still counted against ``max_topics``.
    :param id_pattern: Compiled regex; every candidate id must ``fullmatch`` it
        on BOTH the public and the authorized branch. Defaults to
        :data:`DEFAULT_SAFE_ID`.
    """
    router = APIRouter()

    @router.get("/events")
    async def events(request: Request):  # noqa: ANN202 — FastAPI handler
        # 1. Authenticate (cap-cert + request signature, bodyless).
        identity = await authenticate(request)
        if not identity:
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        # 2. Candidate ids from ?<candidates_param>=a,b,c.
        raw = request.query_params.get(candidates_param) or ""
        candidates = [c.strip() for c in raw.split(",") if c.strip()]
        if len(candidates) > max_candidates:
            # Cap pre-auth so an attacker can't trigger N authorize calls with
            # one request.
            return JSONResponse(
                {"error": "too many candidates"}, status_code=400
            )

        # 3. Per-candidate gate. Public candidates are open-gated; the rest go
        #    through authorize(). Every id is charset-validated on BOTH branches
        #    (a bad id is silently dropped, never proxied).
        authorized: list[str] = []
        truncated = False
        for candidate in candidates:
            if len(authorized) >= max_topics:
                truncated = True
                break
            if public_predicate is not None and public_predicate(candidate):
                if id_pattern.fullmatch(candidate) is None:
                    continue
                authorized.append(candidate)
                continue
            if id_pattern.fullmatch(candidate) is None:
                continue
            if await authorize(identity, candidate):
                authorized.append(candidate)
        if truncated:
            logger.warning(
                "events-proxy: topic cap (%d) reached for %s; extra candidates "
                "won't live-update until reconnect.",
                max_topics,
                identity,
            )

        # 4. Map authorized candidates → upstream topics (caller's transform).
        topics: list[str] = []
        for candidate in authorized:
            topics.extend(topic_mapper(candidate))

        # 5. Firehose-prevention invariant: never subscribe topic-less upstream.
        safe_topics = topics or [_NONE_SENTINEL]

        # 6. Proxy the upstream SSE stream, propagating client disconnect.
        qs = "&".join("topic=" + quote(t, safe="") for t in safe_topics)
        sep = "&" if "?" in upstream_url else "?"
        full_url = f"{upstream_url}{sep}{qs}"

        client = httpx.AsyncClient(timeout=None)

        # Open the upstream BEFORE returning a response so a non-200 surfaces as a
        # 502 to the client (parity with the TS proxy), rather than a 200 with an
        # immediately-empty stream. The stream context is entered manually so it
        # stays open across the StreamingResponse's lifetime and is closed in the
        # generator's finally.
        cm = client.stream("GET", full_url, headers={"Accept": "text/event-stream"})
        try:
            upstream = await cm.__aenter__()
        except httpx.HTTPError:
            await client.aclose()
            return JSONResponse({"error": "upstream unavailable"}, status_code=502)
        except BaseException:
            # A non-HTTPError from the connect (e.g. httpx.InvalidURL, which is NOT
            # an HTTPError subclass, or CancelledError) must not leak the client
            # before it propagates.
            await client.aclose()
            raise
        # Accept any 2xx (parity with the TS proxy's `Response.ok`); anything else
        # surfaces as a 502, not a 200 with an immediately-empty stream.
        if not 200 <= upstream.status_code < 300:
            await cm.__aexit__(None, None, None)
            await client.aclose()
            return JSONResponse({"error": "upstream unavailable"}, status_code=502)

        async def stream():  # noqa: ANN202
            try:
                async for chunk in upstream.aiter_raw():
                    if await request.is_disconnected():
                        break
                    yield chunk
            finally:
                await cm.__aexit__(None, None, None)
                await client.aclose()

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
        )

    return router
