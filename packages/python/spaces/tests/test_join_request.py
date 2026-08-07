"""Device-code space-join pairing — the security properties, not just the flow.

Every test here that carries a security claim is written so it FAILS if the
corresponding guard is removed from ``join_request.py`` (each was verified by
reverting the guard and observing the failure).
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from starfish_identities import generate_device_keys

from starfish_spaces.join_request import (
    CODE_ALPHABET,
    CODE_LENGTH,
    CODE_REJECT_THRESHOLD,
    MAX_REQUEST_TTL_SEC,
    AwaitSpaceJoinGrantOptions,
    ClearSpaceJoinGrantOptions,
    FetchSpaceJoinGrantOptions,
    FetchSpaceJoinRequestOptions,
    PublishSpaceJoinGrantOptions,
    SpaceJoinConflictError,
    SpaceJoinRequestSession,
    StartSpaceJoinRequestOptions,
    await_space_join_grant,
    clear_space_join_grant,
    create_space_join_request,
    fetch_space_join_grant,
    fetch_space_join_request_by_code,
    join_request_from_space_join_request,
    parse_space_join_request,
    publish_space_join_grant,
    random_code,
    start_space_join_request,
    verify_space_join_request_pop,
)
from starfish_spaces.layout import default_space_layout

from tests.fake_rendezvous import AlwaysConflictRendezvous, FakeRendezvous

RENDEZVOUS = {"baseUrl": "https://sync.example.test", "namespace": "dk"}
ORIGIN = "https://myapp.example"


# ── Fixtures / helpers ────────────────────────────────────────────────────────


def _slot_key(code: str) -> str:
    return FakeRendezvous.key_of(default_space_layout.join_session_pull(code))


async def _started(server: FakeRendezvous, **kwargs) -> SpaceJoinRequestSession:
    session = await start_space_join_request(
        StartSpaceJoinRequestOptions(
            origin=kwargs.pop("origin", ORIGIN), rendezvous=RENDEZVOUS, client=server, **kwargs
        )
    )
    return session


MEMBER_CAP = {"kind": "member", "sub": "ed", "nonce": "n1"}
"""Stand-in for the cap ``invite_to_space`` mints."""


async def _approve(
    server: FakeRendezvous, code: str, base_hash: str, sealer: dict[str, str], **kwargs
) -> str | None:
    fetched_request = kwargs.pop("request")
    return await publish_space_join_grant(
        PublishSpaceJoinGrantOptions(
            request=fetched_request,
            code=code,
            space_id=kwargs.pop("space_id", "sp-1"),
            cap=kwargs.pop("cap", MEMBER_CAP),
            sealer=sealer,
            rendezvous=RENDEZVOUS,
            base_hash=base_hash,
            client=server,
            **kwargs,
        )
    )


# ── Code generation ───────────────────────────────────────────────────────────


def test_code_shape_excludes_ambiguous_characters():
    for _ in range(200):
        code = random_code()
        assert len(code) == CODE_LENGTH
        assert re.fullmatch(f"[{CODE_ALPHABET}]+", code)
        # 0/O and 1/I/L are exactly what the alphabet exists to avoid.
        assert not re.search("[0O1IL]", code)


def test_code_rejection_sampling_keeps_the_distribution_uniform():
    # 256 % 31 == 8, so a plain `byte % 31` over-represents A-H by 12.5%.
    assert CODE_REJECT_THRESHOLD == 248
    counts = {c: 0 for c in CODE_ALPHABET}
    draws = 4000
    for _ in range(draws):
        for ch in random_code():
            counts[ch] += 1
    expected = draws * CODE_LENGTH / len(CODE_ALPHABET)
    for ch, n in counts.items():
        assert expected * 0.6 < n < expected * 1.4, f"symbol {ch!r} drawn {n} times, expected ~{expected:.0f}"


# ── Create-only CAS on the request write ──────────────────────────────────────


async def test_first_request_publish_is_create_only_and_succeeds():
    server = FakeRendezvous()
    session = await _started(server)
    await session.publish()

    doc = server.raw(_slot_key(session.code))
    assert doc is not None
    assert doc["v"] == 1 and doc["phase"] == "request"


async def test_second_writer_cannot_create_over_an_occupied_slot():
    """Create-only CAS: a racing publisher on the SAME code is rejected."""
    server = FakeRendezvous()
    first = await _started(server)
    await first.publish()

    # A different session that happens to collide on this code — force the
    # collision rather than hoping for a 1-in-2^39.6 event.
    second = await _started(server)
    second.code = first.code

    with pytest.raises(SpaceJoinConflictError):
        await second.publish()

    # The legitimate publisher's document is still the one in the slot.
    assert server.raw(_slot_key(first.code))["devEdPub"] == first.request["devEdPub"]


def test_space_join_conflict_error_is_a_conflict_error():
    # Regression pin: a bare `except ConflictError` — the convention every
    # other CAS write in this package uses, and what the TS twin lets
    # propagate untouched — must still catch this. It didn't originally:
    # SpaceJoinConflictError subclassed plain Exception, so the "treat this
    # code as compromised" handler callers naturally reach for silently never
    # ran.
    from starfish_sdk.types import ConflictError

    assert issubclass(SpaceJoinConflictError, ConflictError)
    assert isinstance(SpaceJoinConflictError("boom"), ConflictError)
    assert str(SpaceJoinConflictError("boom")) == "boom"


async def test_republish_uses_its_own_remembered_hash():
    server = FakeRendezvous()
    session = await _started(server)
    await session.publish()
    await session.publish()  # same session, its own remembered hash — fine
    assert server.push_calls == 2


async def test_hostile_overwrite_between_publishes_surfaces_as_a_conflict():
    """Own-write CAS: the publisher must NOT silently adopt a hijacked slot."""
    server = FakeRendezvous()
    session = await _started(server)
    await session.publish()

    # A third party overwrites the slot; its hash advances.
    server.force_write(_slot_key(session.code), {"v": 1, "phase": "request", "origin": "https://evil.test"})

    with pytest.raises(SpaceJoinConflictError, match="compromised"):
        await session.publish()


async def test_overlapping_publishes_do_not_self_race():
    """Two in-flight publish() calls on one session must not fake a hijack."""
    import asyncio

    server = FakeRendezvous()
    session = await _started(server)
    await asyncio.gather(session.publish(), session.publish(), session.publish())
    assert server.push_calls == 3


# ── Lookup by code ────────────────────────────────────────────────────────────


async def test_fetch_by_code_returns_none_for_an_unwritten_slot():
    server = FakeRendezvous()
    got = await fetch_space_join_request_by_code(
        FetchSpaceJoinRequestOptions(code="ZZZZZZZZ", rendezvous=RENDEZVOUS, client=server)
    )
    assert got is None


async def test_fetch_by_code_round_trips_and_exposes_the_cas_hash():
    server = FakeRendezvous()
    session = await _started(server, label="My App", requested_scopes=["accounts"])
    await session.publish()

    got = await fetch_space_join_request_by_code(
        FetchSpaceJoinRequestOptions(code=session.code, rendezvous=RENDEZVOUS, client=server)
    )
    assert got is not None
    assert got.request["origin"] == ORIGIN
    assert got.request["label"] == "My App"
    assert got.request["requestedScopes"] == ["accounts"]
    # The hash is what makes the grant a CAS UPDATE rather than a create.
    assert got.hash == server.hash_of(_slot_key(session.code))


# ── Proof-of-possession ───────────────────────────────────────────────────────


async def test_tampered_dev_ed_pub_is_rejected():
    server = FakeRendezvous()
    session = await _started(server)
    await session.publish()

    key = _slot_key(session.code)
    doc = server.raw(key)
    doc["devEdPub"] = generate_device_keys()["edPub"]
    server.force_write(key, doc)

    with pytest.raises(ValueError, match="proof-of-possession"):
        await fetch_space_join_request_by_code(
            FetchSpaceJoinRequestOptions(code=session.code, rendezvous=RENDEZVOUS, client=server)
        )


async def test_tampered_dev_kem_pub_is_rejected():
    """The KEM key the grant gets sealed to cannot be swapped in transit."""
    server = FakeRendezvous()
    session = await _started(server)
    await session.publish()

    key = _slot_key(session.code)
    doc = server.raw(key)
    doc["devKemPub"] = generate_device_keys()["kemPub"]
    server.force_write(key, doc)

    with pytest.raises(ValueError, match="proof-of-possession"):
        await fetch_space_join_request_by_code(
            FetchSpaceJoinRequestOptions(code=session.code, rendezvous=RENDEZVOUS, client=server)
        )


async def test_popsig_is_bound_to_the_code_so_a_request_cannot_be_relocated():
    """Copying a valid request into a DIFFERENT code's slot must not verify."""
    server = FakeRendezvous()
    session = await _started(server)
    await session.publish()

    other_code = "ABCDEFGH"
    server.force_write(_slot_key(other_code), server.raw(_slot_key(session.code)))

    with pytest.raises(ValueError, match="proof-of-possession"):
        await fetch_space_join_request_by_code(
            FetchSpaceJoinRequestOptions(code=other_code, rendezvous=RENDEZVOUS, client=server)
        )


def test_flipped_popsig_bytes_are_rejected():
    created = create_space_join_request(ORIGIN)
    req = dict(created.request)
    req["popSig"] = ("f" if req["popSig"][0] != "f" else "0") + req["popSig"][1:]
    with pytest.raises(ValueError, match="proof-of-possession"):
        verify_space_join_request_pop(parse_space_join_request(req), created.code)


# ── Structural validation ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "field_name,bad",
    [
        ("devEdPub", "a" * 1000),
        ("devEdPub", "abc"),
        ("devKemPub", "z" * 64),  # right length, not hex
        ("popSig", "a" * 500_000),
        ("popSig", "z" * 128),
        ("joinRequestKemSig", "abc"),
    ],
)
def test_hex_fields_are_length_and_charset_checked(field_name, bad):
    created = create_space_join_request(ORIGIN)
    req = dict(created.request)
    req[field_name] = bad
    with pytest.raises(ValueError, match=f"{field_name} is not a valid"):
        parse_space_join_request(req)


@pytest.mark.parametrize(
    "value",
    [
        "https://evil.test\nLooks like app chrome",  # C0 newline
        "https://evil.test\u202Ednuoferehton",  # bidi override
        "https://evil.test\u2066spoof\u2069",  # bidi isolate
        "https://evil.test\u0085",  # C1
    ],
)
def test_origin_rejects_control_and_bidi_characters(value):
    created = create_space_join_request(ORIGIN)
    req = dict(created.request)
    req["origin"] = value
    with pytest.raises(ValueError, match="control or bidi-override"):
        parse_space_join_request(req)


@pytest.mark.parametrize("value", ["My\nApp", "My\u202EApp", "\u2066App\u2069"])
def test_label_rejects_control_and_bidi_characters(value):
    created = create_space_join_request(ORIGIN, label="ok")
    req = dict(created.request)
    req["label"] = value
    with pytest.raises(ValueError, match="control or bidi-override"):
        parse_space_join_request(req)


def test_origin_and_label_are_length_capped():
    created = create_space_join_request(ORIGIN, label="ok")
    long_origin = dict(created.request)
    long_origin["origin"] = "https://a.test/" + "x" * 3000
    with pytest.raises(ValueError, match="origin exceeds max length"):
        parse_space_join_request(long_origin)

    long_label = dict(created.request)
    long_label["label"] = "x" * 500
    with pytest.raises(ValueError, match="label exceeds max length"):
        parse_space_join_request(long_label)


def test_origin_must_parse_as_a_url():
    created = create_space_join_request(ORIGIN)
    for bad in ["not a url at all", "https://", "", "   "]:
        req = dict(created.request)
        req["origin"] = bad
        with pytest.raises(ValueError, match="not a valid URL"):
            parse_space_join_request(req)


@pytest.mark.parametrize(
    "value",
    [
        "http:example.com",
        "http:/example.com",
        "http:///example.com",
        "ftp:example.com",
        "wss:example.com",
        "  http://x.com",
        "mailto:a@b",
        # Backslash right after the colon is an authority marker to WHATWG,
        # identical to a forward slash, for a "special" scheme — regression
        # pin for a bug caught in review: an earlier version of the
        # slash-count normalization only matched `/`, so these were
        # incorrectly REJECTED (opposite verdict from the TS twin).
        "http:\\evil.example",
        "http:/\\evil.example",
        "http:\\/evil.example",
        "http:\\\\evil.example",
    ],
)
def test_origin_accepts_the_same_edge_cases_as_the_ts_twins_whatwg_url(value):
    # Regression pin: Node's `new URL()` (what the TS side validates with)
    # accepts all of these — a special scheme with zero, one, or three+
    # slashes (forward or backward) after the colon, and leading whitespace.
    # `origin` is caller-controlled wire data, so a byte-identical request document must
    # get the same accept/reject verdict from a Python approver as a TS one.
    created = create_space_join_request(ORIGIN)
    req = dict(created.request)
    req["origin"] = value
    parsed = parse_space_join_request(req)
    assert parsed["origin"] == value


@pytest.mark.parametrize("value", ["http:", "http:/", "http://", "http:///", "http: evil.example", "http:  evil.example"])
def test_origin_still_rejects_a_special_scheme_with_no_host(value):
    # "http: evil.example" (space right after the colon, no slash) is a
    # regression pin from a second review round: an earlier version of the
    # authority parsing here let a plain rewrite-then-urlparse approach treat
    # the padded string as a valid (space-containing) host, where `new URL()`
    # rejects it outright — the same "opposite verdict from the TS twin" bug
    # class this whole function exists to close.
    created = create_space_join_request(ORIGIN)
    req = dict(created.request)
    req["origin"] = value
    with pytest.raises(ValueError, match="not a valid URL"):
        parse_space_join_request(req)


def test_origin_host_matches_the_ts_twins_whatwg_parse_not_just_accept_reject():
    # A byte-for-byte accept/reject match isn't enough on its own: for
    # "http:evil.example\\@good.example", `new URL()` resolves host
    # "evil.example" (backslash terminates the authority before the `@`
    # ever gets a chance to look like userinfo), while a naive
    # rewrite-then-urlparse implementation resolves "good.example" instead
    # (urlparse has no concept of backslash-as-terminator, so it treats the
    # whole "evil.example\\@good.example" run as ordinary netloc text and
    # splits userinfo off at the last "@" as usual). Both "accept" the
    # string, but for two different hosts — this pins the actual resolved
    # host, not just whether parsing succeeds.
    from starfish_spaces.join_request import _special_scheme_authority_host

    assert _special_scheme_authority_host("evil.example\\@good.example") == "evil.example"


def test_wrong_phase_or_version_is_not_a_request():
    created = create_space_join_request(ORIGIN)
    for override in [{"phase": "grant"}, {"v": 2}, {"phase": "nonsense"}]:
        req = dict(created.request)
        req.update(override)
        with pytest.raises(ValueError, match="not a phase-'request' payload"):
            parse_space_join_request(req)


def test_non_json_and_non_object_payloads_are_rejected():
    with pytest.raises(ValueError, match="not valid JSON"):
        parse_space_join_request("{nope")
    with pytest.raises(ValueError, match="not an object"):
        parse_space_join_request("[1,2,3]")


# ── Wall-clock-anchored TTL ───────────────────────────────────────────────────


def _with_times(created_at: str | None = None, expires_at: str | None = None):
    created = create_space_join_request(ORIGIN)
    req = dict(created.request)
    if created_at is not None:
        req["createdAt"] = created_at
    if expires_at is not None:
        req["expiresAt"] = expires_at
    return created.code, parse_space_join_request(req)


def _iso_in(**delta) -> str:
    moment = datetime.now(timezone.utc) + timedelta(**delta)
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{moment.microsecond // 1000:03d}Z"


def test_an_expired_request_is_rejected():
    code, req = _with_times(expires_at=_iso_in(seconds=-1))
    with pytest.raises(ValueError, match="expired"):
        verify_space_join_request_pop(req, code)


@pytest.mark.parametrize("garbage", ["not-a-real-date", "", "Infinity", "   ", "NaN"])
def test_a_garbage_expires_at_fails_closed(garbage):
    """An unparseable timestamp must REJECT, never read as 'not expired'."""
    code, req = _with_times(expires_at=garbage)
    with pytest.raises(ValueError, match="expired"):
        verify_space_join_request_pop(req, code)


def test_expiry_just_inside_the_cap_is_accepted():
    code, req = _with_times(expires_at=_iso_in(seconds=MAX_REQUEST_TTL_SEC - 30))
    verify_space_join_request_pop(req, code)  # must not raise


def test_expiry_beyond_the_cap_is_rejected():
    code, req = _with_times(expires_at=_iso_in(seconds=MAX_REQUEST_TTL_SEC + 30))
    with pytest.raises(ValueError, match="exceeds the maximum"):
        verify_space_join_request_pop(req, code)


def test_created_at_relative_window_cannot_bypass_the_cap():
    """The regression the wall-clock anchor exists for.

    An attacker controls BOTH timestamps (neither is covered by popSig). Placing
    them a year out while keeping their DIFFERENCE inside the cap makes the code
    look freshly issued to any createdAt-relative check, yet keeps it valid for
    the next year. Anchoring to the parsing call's own clock closes it.
    """
    code, req = _with_times(
        created_at=_iso_in(days=365, minutes=-30),
        expires_at=_iso_in(days=365),
    )
    # The self-reported window is a harmless-looking 30 minutes...
    assert timedelta(minutes=29) < (
        datetime.fromisoformat(req["expiresAt"].replace("Z", "+00:00"))
        - datetime.fromisoformat(req["createdAt"].replace("Z", "+00:00"))
    ) < timedelta(minutes=31)
    # ...but measured against the real clock it is a year, so it must be rejected.
    with pytest.raises(ValueError, match="exceeds the maximum"):
        verify_space_join_request_pop(req, code)


def test_created_at_is_purely_informational():
    """A garbage createdAt is fine — it feeds no security decision."""
    code, req = _with_times(created_at="not-a-real-date")
    verify_space_join_request_pop(req, code)  # must not raise


def test_create_clamps_an_oversized_ttl():
    created = create_space_join_request(ORIGIN, ttl_sec=365 * 24 * 60 * 60)
    span = datetime.fromisoformat(created.request["expiresAt"].replace("Z", "+00:00")) - datetime.fromisoformat(
        created.request["createdAt"].replace("Z", "+00:00")
    )
    assert span <= timedelta(seconds=MAX_REQUEST_TTL_SEC)
    # And the clamped result is one this package's own parser accepts.
    verify_space_join_request_pop(parse_space_join_request(created.request), created.code)


def test_create_does_not_clamp_a_negative_ttl():
    created = create_space_join_request(ORIGIN, ttl_sec=-60)
    with pytest.raises(ValueError, match="expired"):
        verify_space_join_request_pop(parse_space_join_request(created.request), created.code)


# ── Grant write: CAS UPDATE, never create ─────────────────────────────────────


async def test_grant_requires_a_base_hash():
    server = FakeRendezvous()
    session = await _started(server)
    await session.publish()
    sealer = generate_device_keys()

    for missing in (None, ""):
        with pytest.raises(ValueError, match="base_hash is required"):
            await _approve(server, session.code, missing, sealer, request=session.request)


async def test_grant_never_creates_a_document_in_an_empty_slot():
    """A grant may only ever REPLACE a request it actually read."""
    server = FakeRendezvous()
    created = create_space_join_request(ORIGIN)
    sealer = generate_device_keys()

    # Nothing was ever published under this code.
    assert server.raw(_slot_key(created.code)) is None
    with pytest.raises(SpaceJoinConflictError):
        await _approve(server, created.code, "h-nonexistent", sealer, request=created.request)
    assert server.raw(_slot_key(created.code)) is None


async def test_grant_with_a_stale_base_hash_conflicts():
    server = FakeRendezvous()
    session = await _started(server)
    await session.publish()
    fetched = await fetch_space_join_request_by_code(
        FetchSpaceJoinRequestOptions(code=session.code, rendezvous=RENDEZVOUS, client=server)
    )
    # Someone else writes between the read and the approve.
    server.force_write(_slot_key(session.code), {"v": 1, "phase": "request", "origin": ORIGIN})

    with pytest.raises(SpaceJoinConflictError, match="compromised"):
        await _approve(
            server, session.code, fetched.hash, generate_device_keys(), request=fetched.request
        )


async def test_grant_transitions_the_same_slot_from_request_to_grant():
    """One collection, one address, two phases."""
    server = FakeRendezvous()
    session = await _started(server)
    await session.publish()
    key = _slot_key(session.code)
    assert server.raw(key)["phase"] == "request"

    fetched = await fetch_space_join_request_by_code(
        FetchSpaceJoinRequestOptions(code=session.code, rendezvous=RENDEZVOUS, client=server)
    )
    await _approve(server, session.code, fetched.hash, generate_device_keys(), request=fetched.request)

    # Same key, no second slot anywhere in the store.
    assert list(server.docs) == [key]
    assert server.raw(key)["phase"] == "grant"


# ── Seal / unseal ─────────────────────────────────────────────────────────────


async def _full_flow(server: FakeRendezvous, sealer=None, space_id=None):
    session = await _started(server)
    await session.publish()
    fetched = await fetch_space_join_request_by_code(
        FetchSpaceJoinRequestOptions(code=session.code, rendezvous=RENDEZVOUS, client=server)
    )
    sealer = sealer or generate_device_keys()
    await _approve(
        server,
        session.code,
        fetched.hash,
        sealer,
        request=fetched.request,
        space_id=space_id or "sp-1",
    )
    return session, sealer


async def test_round_trip_delivers_the_cap_only_to_the_requester():
    server = FakeRendezvous()
    session, sealer = await _full_flow(server)

    grant = await fetch_space_join_grant(session)
    assert grant is not None
    assert grant.space_id == "sp-1"
    assert grant.cap == MEMBER_CAP
    assert grant.sealed_by == sealer["edPub"]


async def test_the_slot_never_exposes_the_cap_in_plaintext():
    server = FakeRendezvous()
    session, _ = await _full_flow(server)
    on_the_wire = json.dumps(server.raw(_slot_key(session.code)))
    assert "sp-1" not in on_the_wire
    assert "member" not in on_the_wire


async def test_a_different_kem_key_cannot_open_the_grant():
    server = FakeRendezvous()
    session, _ = await _full_flow(server)
    eavesdropper = SpaceJoinRequestSession(
        request=session.request,
        device=generate_device_keys(),
        code=session.code,
        rendezvous=RENDEZVOUS,
        client=server,
    )
    with pytest.raises(ValueError):
        await fetch_space_join_grant(eavesdropper)


async def test_aad_binds_the_grant_to_its_code_blocking_relocation():
    """A grant lifted into another code's slot must not open there."""
    server = FakeRendezvous()
    session, _ = await _full_flow(server)

    other_code = "MNPQRSTU"
    server.force_write(_slot_key(other_code), server.raw(_slot_key(session.code)))

    relocated = SpaceJoinRequestSession(
        request=session.request,
        device=session.device,  # same keys, so ONLY the AAD differs
        code=other_code,
        rendezvous=RENDEZVOUS,
        client=server,
    )
    with pytest.raises(ValueError, match="decryption failed"):
        await fetch_space_join_grant(relocated)

    # Sanity: the very same blob still opens at its own code.
    assert await fetch_space_join_grant(session) is not None


async def test_tampered_ciphertext_is_rejected():
    server = FakeRendezvous()
    session, _ = await _full_flow(server)
    key = _slot_key(session.code)
    doc = server.raw(key)
    ct = doc["sealed"]["ct"]
    doc["sealed"]["ct"] = ("A" if ct[0] != "A" else "B") + ct[1:]
    server.force_write(key, doc)

    with pytest.raises(ValueError):
        await fetch_space_join_grant(session)


# ── TOFU sealer pinning ───────────────────────────────────────────────────────


async def test_expected_sealer_accepts_the_pinned_key():
    server = FakeRendezvous()
    session, sealer = await _full_flow(server)
    grant = await fetch_space_join_grant(
        session, FetchSpaceJoinGrantOptions(expected_sealer=sealer["edPub"])
    )
    assert grant is not None and grant.sealed_by == sealer["edPub"]


async def test_a_later_writer_cannot_replace_an_established_pairing():
    """TOFU: re-sealing with a different key is refused once pinned."""
    server = FakeRendezvous()
    session, first_sealer = await _full_flow(server)
    pinned = (await fetch_space_join_grant(session)).sealed_by
    assert pinned == first_sealer["edPub"]

    # An attacker who learned the code re-seals its own grant into the slot,
    # correctly AAD-bound to this code and to the requester's real KEM key.
    attacker = generate_device_keys()
    key = _slot_key(session.code)
    await _approve(
        server,
        session.code,
        server.hash_of(key),
        attacker,
        request=session.request,
        space_id="sp-attacker",
    )

    # Unpinned, it opens — this is the documented first-read trust gap.
    assert (await fetch_space_join_grant(session)).space_id == "sp-attacker"
    # Pinned, it is refused.
    with pytest.raises(ValueError, match="required sealer"):
        await fetch_space_join_grant(session, FetchSpaceJoinGrantOptions(expected_sealer=pinned))


# ── Phase gating ──────────────────────────────────────────────────────────────


async def test_fetch_grant_returns_none_while_the_slot_is_still_a_request():
    server = FakeRendezvous()
    session = await _started(server)
    await session.publish()
    assert server.raw(_slot_key(session.code))["phase"] == "request"
    assert await fetch_space_join_grant(session) is None


async def test_fetch_grant_returns_none_on_an_empty_slot():
    server = FakeRendezvous()
    session = await _started(server)
    assert await fetch_space_join_grant(session) is None


async def test_fetch_grant_treats_any_non_grant_phase_as_a_wait_state():
    """Matches the TypeScript twin: only ``phase == "grant"`` resolves."""
    server = FakeRendezvous()
    session = await _started(server)
    server.force_write(_slot_key(session.code), {"v": 1, "phase": "something-else"})
    assert await fetch_space_join_grant(session) is None


async def test_fetch_request_by_code_returns_none_once_the_slot_is_a_grant():
    """An already-approved slot has no pending request to approve."""
    server = FakeRendezvous()
    session, _ = await _full_flow(server)
    assert server.raw(_slot_key(session.code))["phase"] == "grant"
    got = await fetch_space_join_request_by_code(
        FetchSpaceJoinRequestOptions(code=session.code, rendezvous=RENDEZVOUS, client=server)
    )
    assert got is None


async def test_fetch_grant_rejects_a_malformed_sealed_blob():
    server = FakeRendezvous()
    session = await _started(server)
    server.force_write(_slot_key(session.code), {"v": 1, "phase": "grant", "sealed": {"nope": 1}})
    with pytest.raises(ValueError, match="malformed sealed blob"):
        await fetch_space_join_grant(session)


async def test_grant_slot_is_repollable_and_not_cleared_after_a_read():
    """A live pairing is genuinely re-read over its lifetime."""
    server = FakeRendezvous()
    session, _ = await _full_flow(server)
    first = await fetch_space_join_grant(session)
    second = await fetch_space_join_grant(session)
    assert first is not None and second is not None
    assert first.space_id == second.space_id == "sp-1"
    assert server.raw(_slot_key(session.code))["phase"] == "grant"


# ── Await ─────────────────────────────────────────────────────────────────────


async def test_await_returns_once_the_grant_lands():
    server = FakeRendezvous()
    session, _ = await _full_flow(server)
    grant = await await_space_join_grant(
        session, AwaitSpaceJoinGrantOptions(timeout_sec=1, poll_delay=lambda _n: 0.0)
    )
    assert grant.space_id == "sp-1"


async def test_await_times_out_while_nothing_is_approved():
    server = FakeRendezvous()
    session = await _started(server)
    await session.publish()
    with pytest.raises(TimeoutError):
        await await_space_join_grant(
            session, AwaitSpaceJoinGrantOptions(timeout_sec=0.05, poll_delay=lambda _n: 0.0)
        )


async def test_await_keeps_polling_through_a_transient_error():
    server = FakeRendezvous()
    session, _ = await _full_flow(server)

    calls = {"n": 0}
    real_pull = server.pull

    async def flaky_pull(path):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("network blip")
        return await real_pull(path)

    server.pull = flaky_pull
    grant = await await_space_join_grant(
        session, AwaitSpaceJoinGrantOptions(timeout_sec=2, poll_delay=lambda _n: 0.0)
    )
    assert grant.space_id == "sp-1"
    assert calls["n"] >= 2


async def test_await_fails_fast_on_a_malformed_grant_instead_of_polling_to_timeout():
    # Regression pin: fetch_space_join_grant's own failures are all
    # ValueError — a real integrity signal, not a wait state — and must
    # reraise on the FIRST attempt rather than being retried to the
    # deadline. Proven by counting pulls: a 60s timeout with a zero poll
    # delay would spin through many iterations fast if this fell through to
    # the generic swallow-and-retry path; instead exactly one pull happens.
    server = FakeRendezvous()
    session = await _started(server)
    server.force_write(_slot_key(session.code), {"v": 1, "phase": "grant", "sealed": {"nope": 1}})

    calls = {"n": 0}
    real_pull = server.pull

    async def counting_pull(path):
        calls["n"] += 1
        return await real_pull(path)

    server.pull = counting_pull
    with pytest.raises(ValueError, match="malformed sealed blob"):
        await await_space_join_grant(
            session, AwaitSpaceJoinGrantOptions(timeout_sec=60, poll_delay=lambda _n: 0.0)
        )
    assert calls["n"] == 1


# ── Clear ─────────────────────────────────────────────────────────────────────


async def test_clear_empties_the_slot():
    server = FakeRendezvous()
    session, _ = await _full_flow(server)
    await clear_space_join_grant(
        ClearSpaceJoinGrantOptions(code=session.code, rendezvous=RENDEZVOUS, client=server)
    )
    assert server.raw(_slot_key(session.code)) == {}
    assert await fetch_space_join_grant(session) is None


async def test_clear_is_idempotent_and_works_on_a_never_written_slot():
    server = FakeRendezvous()
    await clear_space_join_grant(
        ClearSpaceJoinGrantOptions(code="NEVERUSD", rendezvous=RENDEZVOUS, client=server)
    )
    # Double-unpair must not fail.
    await clear_space_join_grant(
        ClearSpaceJoinGrantOptions(code="NEVERUSD", rendezvous=RENDEZVOUS, client=server)
    )


async def test_clear_gives_up_after_repeated_conflicts():
    server = AlwaysConflictRendezvous()
    with pytest.raises(SpaceJoinConflictError, match="too many base-hash conflicts"):
        await clear_space_join_grant(
            ClearSpaceJoinGrantOptions(code="ABCDEFGH", rendezvous=RENDEZVOUS, client=server)
        )
    assert server.push_calls == 3


async def test_clear_permanently_retires_the_code_a_fresh_create_only_publish_conflicts():
    """Clearing overwrites the slot with ``{}`` rather than deleting it, so the
    slot is no longer "unwritten" -- matches the module's own claim that
    clearing "stops the CODE from resolving to a usable grant again", not that
    it frees the code for reuse. Codes are always freshly random (~39.6 bits),
    so this never matters in practice, but a regression here (e.g. clear
    switching to a real delete) would silently change what a stale/replayed
    code can do, so it is worth pinning.
    """
    server = FakeRendezvous()
    session, _ = await _full_flow(server)
    code = session.code
    await clear_space_join_grant(
        ClearSpaceJoinGrantOptions(code=code, rendezvous=RENDEZVOUS, client=server)
    )

    reused = SpaceJoinRequestSession(
        request=create_space_join_request(ORIGIN).request,
        device=generate_device_keys(),
        code=code,
        rendezvous=RENDEZVOUS,
        client=server,
    )
    with pytest.raises(SpaceJoinConflictError):
        await reused.publish()


# ── Independent sessions ────────────────────────────────────────────────────


async def test_two_independent_codes_do_not_interfere():
    server = FakeRendezvous()
    session_a, sealer_a = await _full_flow(server, space_id="sp-a")
    session_b, sealer_b = await _full_flow(server, space_id="sp-b")
    assert session_a.code != session_b.code

    grant_a = await fetch_space_join_grant(session_a)
    grant_b = await fetch_space_join_grant(session_b)
    assert grant_a is not None and grant_b is not None
    assert grant_a.space_id == "sp-a"
    assert grant_a.sealed_by == sealer_a["edPub"]
    assert grant_b.space_id == "sp-b"
    assert grant_b.sealed_by == sealer_b["edPub"]

    # Clearing one code's slot must not touch the other.
    await clear_space_join_grant(
        ClearSpaceJoinGrantOptions(code=session_a.code, rendezvous=RENDEZVOUS, client=server)
    )
    assert await fetch_space_join_grant(session_a) is None
    still_there = await fetch_space_join_grant(session_b)
    assert still_there is not None
    assert still_there.space_id == "sp-b"


# ── Bridge to invite_to_space ─────────────────────────────────────────────────


async def test_join_request_from_space_join_request_matches_make_join_request_shape():
    from starfish_spaces.layout import default_user_id_from_ed_pub
    from starfish_spaces.request_verify import verify_kem_sig

    created = create_space_join_request(ORIGIN)
    raw = await join_request_from_space_join_request(created.request)
    parsed = json.loads(raw)

    assert set(parsed) == {"edPub", "kemPub", "userId", "kemSig"}
    assert parsed["edPub"] == created.request["devEdPub"]
    assert parsed["kemPub"] == created.request["devKemPub"]
    assert parsed["userId"] == await default_user_id_from_ed_pub(created.request["devEdPub"])
    # The kemSig must satisfy the same verifier parse_join_request uses.
    assert verify_kem_sig(parsed["edPub"], parsed["kemPub"], parsed["kemSig"])
    assert not verify_kem_sig(parsed["edPub"], generate_device_keys()["kemPub"], parsed["kemSig"])


async def test_join_request_accepts_a_custom_user_id_hook():
    created = create_space_join_request(ORIGIN)

    async def custom(_ed_pub: str) -> str:
        return "custom-user-id"

    parsed = json.loads(await join_request_from_space_join_request(created.request, custom))
    assert parsed["userId"] == "custom-user-id"


async def test_the_bridged_join_request_is_accepted_by_parse_join_request():
    """End-to-end with the REAL invite-side parser this feeds."""
    from starfish_spaces.invite_helpers import parse_join_request
    from tests.helpers import make_fake_session

    created = create_space_join_request(ORIGIN)
    raw = await join_request_from_space_join_request(created.request)
    subject = await parse_join_request(json.loads(raw), make_fake_session())
    assert subject["edPubHex"] == created.request["devEdPub"]
    assert subject["kemPubHex"] == created.request["devKemPub"]


# ── Layout ────────────────────────────────────────────────────────────────────


def test_join_session_paths_use_the_documented_template():
    """Pinned to the ``joinsessions`` collection the design registers.

    Deliberately SHARES the ``_pairing/`` prefix with the unrelated own-device
    QR pairing rendezvous (``pairing_pull``/``pairing_push``, storage path
    ``_pairing/{rendezvousId}``) rather than a separate top-level namespace —
    this genuinely is a pairing flow, and the two coexist without collision:
    the deployed system already hosted two-segment paths
    (``_pairing/requests/{code}``, ``_pairing/snapshots/{sessionId}``)
    alongside that same 1-segment wildcard collection with no issue, so
    ``_pairing/session/{code}`` (also two segments) is safe the same way.
    """
    assert default_space_layout.join_session_pull("ABCD1234") == "/pull/_pairing/session/ABCD1234"
    assert default_space_layout.join_session_push("ABCD1234") == "/push/_pairing/session/ABCD1234"


def test_join_session_paths_are_distinguishable_from_device_pairing():
    """Same top-level prefix as device pairing, but a distinct sub-path — the
    ``session/`` segment is what keeps `_pairing/{rendezvousId}`'s 1-segment
    wildcard from ever matching a join-session document."""
    assert default_space_layout.join_session_pull("ABCD1234").startswith("/pull/_pairing/session/")


def test_poll_backoff_matches_the_typescript_twin():
    from starfish_spaces.join_request import default_poll_delay

    assert [default_poll_delay(n) for n in range(6)] == [1.0, 2.0, 4.0, 5.0, 5.0, 5.0]


def test_join_session_paths_escape_a_hostile_code():
    """A code is user-supplied; it must not be able to walk the path."""
    assert default_space_layout.join_session_pull("../../etc") == "/pull/_pairing/session/..%2F..%2Fetc"
