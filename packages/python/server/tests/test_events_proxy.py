"""Tests for ``create_events_proxy_router`` — the authenticated SSE proxy."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from starfish_server.events_proxy import create_events_proxy_router

_UPSTREAM = "http://upstream.test/events"


def _build_app(
    *,
    identity: str | None,
    authorized: set[str],
    public: set[str] | None = None,
    max_candidates: int = 16,
    max_topics: int = 4,
    max_public_topics: int | None = None,
):
    async def authenticate(request: Request) -> str | None:
        return identity

    async def authorize(ident: str, candidate: str) -> bool:
        return candidate in authorized

    def topic_mapper(candidate: str) -> list[str]:
        return [f"topic-{candidate}"]

    public_pred = (lambda c: c in public) if public is not None else None

    router = create_events_proxy_router(
        authenticate=authenticate,
        candidates_param="ids",
        authorize=authorize,
        topic_mapper=topic_mapper,
        upstream_url=_UPSTREAM,
        max_candidates=max_candidates,
        max_topics=max_topics,
        public_predicate=public_pred,
        max_public_topics=max_public_topics,
    )
    app = FastAPI()
    app.include_router(router)
    return app


def _captured_topics(route) -> list[str]:
    """Topics from the single upstream call captured by respx."""
    assert route.called
    url = str(route.calls[0].request.url)
    return parse_qs(urlsplit(url).query).get("topic", [])


@pytest.mark.asyncio
async def test_401_when_unauthenticated() -> None:
    app = _build_app(identity=None, authorized=set())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/events?ids=a,b")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_400_over_max_candidates() -> None:
    app = _build_app(identity="alice", authorized=set(), max_candidates=2)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/events?ids=a,b,c")
    assert resp.status_code == 400


@respx.mock
@pytest.mark.asyncio
async def test_topic_cap_truncation() -> None:
    route = respx.get(url__startswith=_UPSTREAM).mock(
        return_value=httpx.Response(200, text="data: ok\n\n")
    )
    # All 6 authorized, but max_topics=4 → only 4 proxied.
    ids = ["p0", "p1", "p2", "p3", "p4", "p5"]
    app = _build_app(identity="alice", authorized=set(ids), max_topics=4)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/events?ids=" + ",".join(ids))
    assert resp.status_code == 200
    topics = _captured_topics(route)
    assert topics == ["topic-p0", "topic-p1", "topic-p2", "topic-p3"]


@respx.mock
@pytest.mark.asyncio
async def test_none_sentinel_when_nothing_authorized() -> None:
    route = respx.get(url__startswith=_UPSTREAM).mock(
        return_value=httpx.Response(200, text="")
    )
    app = _build_app(identity="alice", authorized=set())  # nothing authorized
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/events?ids=a,b,c")
    assert resp.status_code == 200
    assert _captured_topics(route) == ["__none__"]


@respx.mock
@pytest.mark.asyncio
async def test_id_charset_rejection() -> None:
    route = respx.get(url__startswith=_UPSTREAM).mock(
        return_value=httpx.Response(200, text="")
    )
    # "bad id" contains a space → fails DEFAULT_SAFE_ID fullmatch even though
    # it's in the authorized set; "good" passes.
    app = _build_app(identity="alice", authorized={"good", "bad id"})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/events?ids=good,bad id")
    assert resp.status_code == 200
    assert _captured_topics(route) == ["topic-good"]


@respx.mock
@pytest.mark.asyncio
async def test_502_when_upstream_not_ok() -> None:
    # A non-200 upstream surfaces as a 502 to the client (parity with the TS
    # proxy), not a 200 with an empty stream.
    respx.get(url__startswith=_UPSTREAM).mock(return_value=httpx.Response(503))
    app = _build_app(identity="alice", authorized={"a"})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/events?ids=a")
    assert resp.status_code == 502


@respx.mock
@pytest.mark.asyncio
async def test_public_candidate_bad_id_dropped() -> None:
    # A PUBLIC candidate that fails id_pattern must be dropped on the public
    # branch too (not just the authorize branch), closing the bridge-sanitizer
    # collision channel for malformed public ids.
    route = respx.get(url__startswith=_UPSTREAM).mock(
        return_value=httpx.Response(200, text="")
    )
    app = _build_app(identity="alice", authorized=set(), public={"pub", "bad pub"})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/events?ids=pub,bad pub")
    assert resp.status_code == 200
    assert _captured_topics(route) == ["topic-pub"]


@respx.mock
@pytest.mark.asyncio
async def test_public_predicate_open_gates() -> None:
    route = respx.get(url__startswith=_UPSTREAM).mock(
        return_value=httpx.Response(200, text="")
    )
    # "pub" is public (open-gated, no authorize); "priv" is not authorized.
    app = _build_app(identity="alice", authorized=set(), public={"pub"})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/events?ids=pub,priv")
    assert resp.status_code == 200
    assert _captured_topics(route) == ["topic-pub"]


# ── max_public_topics: cap the public fan-out only ───────────────────────────


@respx.mock
@pytest.mark.asyncio
async def test_public_only_cap_truncates_public_not_private() -> None:
    # The octochat scenario: cap the cheap-to-spoof PUBLIC fan-out, but private
    # candidates that follow the capped publics in the list must STILL authorize.
    route = respx.get(url__startswith=_UPSTREAM).mock(return_value=httpx.Response(200, text=""))
    app = _build_app(
        identity="alice",
        authorized={"priv1"},
        public={"pub1", "pub2", "pub3"},
        max_topics=10,
        max_public_topics=2,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/events?ids=pub1,pub2,pub3,priv1")
    assert resp.status_code == 200
    # pub1,pub2 fill the public cap; pub3 is skipped; priv1 still authorizes.
    assert _captured_topics(route) == ["topic-pub1", "topic-pub2", "topic-priv1"]


@respx.mock
@pytest.mark.asyncio
async def test_max_public_topics_none_leaves_public_uncapped() -> None:
    # Default (None) preserves the single-cap behaviour: all public pass, bounded
    # only by max_topics.
    route = respx.get(url__startswith=_UPSTREAM).mock(return_value=httpx.Response(200, text=""))
    app = _build_app(identity="alice", authorized=set(), public={"a", "b", "c"}, max_topics=10)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/events?ids=a,b,c")
    assert resp.status_code == 200
    assert sorted(_captured_topics(route)) == ["topic-a", "topic-b", "topic-c"]


@respx.mock
@pytest.mark.asyncio
async def test_total_max_topics_still_bounds_public_plus_private() -> None:
    # max_public_topics is generous, but max_topics caps the TOTAL (public+private).
    route = respx.get(url__startswith=_UPSTREAM).mock(return_value=httpx.Response(200, text=""))
    app = _build_app(
        identity="alice",
        authorized={"priv1", "priv2"},
        public={"pub1"},
        max_topics=2,
        max_public_topics=10,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/events?ids=pub1,priv1,priv2")
    assert resp.status_code == 200
    # pub1 + priv1 fill max_topics=2; priv2 truncated.
    assert _captured_topics(route) == ["topic-pub1", "topic-priv1"]
