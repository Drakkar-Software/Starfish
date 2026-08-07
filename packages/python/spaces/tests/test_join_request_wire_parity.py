"""Cross-language wire parity with the TypeScript ``join-request.ts`` twin.

Both languages speak the SAME JSON on the rendezvous slot, so these are the
literals that must never drift. Python-side names are snake_case, but the WIRE
stays camelCase — the convention every other shared shape in this package
already follows (see :mod:`starfish_spaces.token_types`, whose ``JoinRequest``
is ``{edPub, kemPub, userId, kemSig}``, and
:meth:`starfish_spaces.config.ObjectNode.to_dict`, which emits ``parentId`` from
a ``parent_id`` attribute).

Two directions are covered:

- **TS → Python**: a payload dict written out by hand exactly as the TypeScript
  side emits it must be accepted by :func:`parse_space_join_request` and pass
  :func:`verify_space_join_request_pop`.
- **Python → TS**: what :func:`create_space_join_request` produces must contain
  exactly the agreed key set, with the agreed value shapes, and its
  proof-of-possession must be computed over the byte-exact canonical JSON that
  TS's ``JSON.stringify({code, devEdPub, devKemPub})`` produces.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from starfish_identities import generate_device_keys
from starfish_protocol.suites import ed25519 as ed25519_suite

from starfish_spaces.join_request import (
    GRANT_ENVELOPE_KIND,
    GRANT_ENVELOPE_VERSION,
    create_space_join_request,
    parse_space_join_request,
    pop_signing_input,
    verify_space_join_request_pop,
)
from starfish_spaces.request_verify import sign_kem_sig

# ── The frozen wire contract ──────────────────────────────────────────────────

REQUEST_REQUIRED_KEYS = {
    "v",
    "phase",
    "devEdPub",
    "devKemPub",
    "popSig",
    "joinRequestKemSig",
    "origin",
    "createdAt",
    "expiresAt",
}
REQUEST_OPTIONAL_KEYS = {"label", "requestedScopes"}
GRANT_KEYS = {"v", "phase", "sealed", "grantedAt"}


def _iso_in(**delta) -> str:
    moment = datetime.now(timezone.utc) + timedelta(**delta)
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{moment.microsecond // 1000:03d}Z"


# ── pop signing input: the byte-exact canonical form ──────────────────────────


def test_pop_signing_input_is_byte_identical_to_js_json_stringify():
    """TS computes ``JSON.stringify({code, devEdPub, devKemPub})``.

    Insertion-ordered keys, no whitespace, no domain-separation prefix. If
    Python's serialization drifts by even a space, no signature verifies across
    the two languages.
    """
    got = pop_signing_input("ABCDEFGH", "aa" * 32, "bb" * 32)
    expected = (
        '{"code":"ABCDEFGH",'
        f'"devEdPub":"{"aa" * 32}",'
        f'"devKemPub":"{"bb" * 32}"}}'
    ).encode("utf-8")
    assert got == expected


def test_pop_signing_input_key_order_is_load_bearing():
    """A reordered serialization must NOT produce the same bytes."""
    reordered = json.dumps(
        {"devEdPub": "aa" * 32, "devKemPub": "bb" * 32, "code": "ABCDEFGH"},
        separators=(",", ":"),
    ).encode("utf-8")
    assert pop_signing_input("ABCDEFGH", "aa" * 32, "bb" * 32) != reordered


# ── TS → Python ───────────────────────────────────────────────────────────────


def _ts_style_request(code: str, device: dict[str, str], **overrides) -> dict:
    """A request document constructed exactly the way the TS twin emits one."""
    pop_sig = ed25519_suite.sign(
        pop_signing_input(code, device["edPub"], device["kemPub"]), device["edPriv"]
    ).hex()
    doc = {
        "v": 1,
        "phase": "request",
        "devEdPub": device["edPub"],
        "devKemPub": device["kemPub"],
        "popSig": pop_sig,
        "joinRequestKemSig": sign_kem_sig(device["kemPub"], device["edPriv"]),
        "origin": "https://myapp.example",
        "label": "My App",
        "requestedScopes": ["accounts", "automations"],
        "createdAt": _iso_in(seconds=0),
        "expiresAt": _iso_in(minutes=5),
    }
    doc.update(overrides)
    return doc


def test_python_accepts_a_typescript_shaped_request():
    device = generate_device_keys()
    code = "ABCDEFGH"
    doc = _ts_style_request(code, device)

    # Exactly as it would arrive off the wire: a JSON string.
    parsed = parse_space_join_request(json.dumps(doc))
    verify_space_join_request_pop(parsed, code)

    assert parsed["devEdPub"] == device["edPub"]
    assert parsed["requestedScopes"] == ["accounts", "automations"]


def test_python_accepts_a_typescript_request_without_the_optional_fields():
    device = generate_device_keys()
    code = "ABCDEFGH"
    doc = _ts_style_request(code, device)
    for optional in REQUEST_OPTIONAL_KEYS:
        doc.pop(optional)

    parsed = parse_space_join_request(json.dumps(doc))
    verify_space_join_request_pop(parsed, code)
    assert "label" not in parsed and "requestedScopes" not in parsed


def test_python_rejects_a_typescript_request_signed_for_another_code():
    """The AAD/PoP binding is the code — cross-language too."""
    device = generate_device_keys()
    doc = _ts_style_request("ABCDEFGH", device)
    with pytest.raises(ValueError, match="proof-of-possession"):
        verify_space_join_request_pop(parse_space_join_request(doc), "MNPQRSTU")


def test_python_accepts_the_js_toisostring_timestamp_format():
    """JS ``Date.toISOString()`` is ``YYYY-MM-DDTHH:MM:SS.mmmZ``."""
    device = generate_device_keys()
    code = "ABCDEFGH"
    expires = datetime.now(timezone.utc) + timedelta(minutes=5)
    js_style = expires.strftime("%Y-%m-%dT%H:%M:%S.") + f"{expires.microsecond // 1000:03d}Z"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", js_style)

    doc = _ts_style_request(code, device, expiresAt=js_style)
    verify_space_join_request_pop(parse_space_join_request(doc), code)


# ── Python → TS ───────────────────────────────────────────────────────────────


def test_python_emits_exactly_the_agreed_request_keys():
    created = create_space_join_request(
        "https://myapp.example", label="My App", requested_scopes=["accounts"]
    )
    assert set(created.request) == REQUEST_REQUIRED_KEYS | REQUEST_OPTIONAL_KEYS


def test_python_omits_absent_optionals_rather_than_emitting_null():
    """TS writes ``...(label ? {label} : {})`` — an explicit null is NOT the same."""
    created = create_space_join_request("https://myapp.example")
    assert set(created.request) == REQUEST_REQUIRED_KEYS
    assert "label" not in created.request
    assert "requestedScopes" not in created.request


def test_python_request_field_types_match_the_contract():
    created = create_space_join_request(
        "https://myapp.example", label="My App", requested_scopes=["accounts"]
    )
    req = created.request
    assert req["v"] == 1
    assert req["phase"] == "request"
    assert re.fullmatch(r"[0-9a-f]{64}", req["devEdPub"])
    assert re.fullmatch(r"[0-9a-f]{64}", req["devKemPub"])
    assert re.fullmatch(r"[0-9a-f]{128}", req["popSig"])
    assert re.fullmatch(r"[0-9a-f]{128}", req["joinRequestKemSig"])
    assert isinstance(req["requestedScopes"], list)
    for stamp in (req["createdAt"], req["expiresAt"]):
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", stamp)


def test_the_request_document_is_json_serialisable_as_is():
    """It is pushed straight to the rendezvous — no adapter layer in between."""
    created = create_space_join_request("https://myapp.example", label="My App")
    assert json.loads(json.dumps(created.request)) == created.request


def test_no_session_id_anywhere_in_the_merged_design():
    """The retired two-slot design's high-entropy sessionId must be gone."""
    created = create_space_join_request("https://myapp.example")
    assert "sessionId" not in created.request
    assert not any(k.lower() == "sessionid" for k in created.request)


def test_no_rendezvous_field_rides_inside_the_request():
    """Dropped deliberately: an approver must never route by an attacker-supplied host."""
    created = create_space_join_request("https://myapp.example")
    assert "rendezvous" not in created.request


def test_the_phase_discriminant_is_the_only_kind_marker():
    """The merged design discriminates on ``phase``, not the old ``kind`` string."""
    created = create_space_join_request("https://myapp.example")
    assert created.request["phase"] == "request"
    assert "kind" not in created.request


def test_grant_envelope_constants_are_pinned():
    """Inside the seal, not on the slot — but still a shared cross-language shape.

    A grant sealed by one language must unseal in the other, so the envelope's
    ``kind`` string and its FLAT ``{spaceId, cap}`` layout are both frozen.
    """
    assert GRANT_ENVELOPE_VERSION == 1
    assert GRANT_ENVELOPE_KIND == "starfish-space-join-grant"


async def test_sealed_envelope_is_flat_space_id_and_cap():
    """Open the seal directly and pin the exact plaintext the TS twin writes."""
    import json as _json

    from starfish_keyring import SealedBlob, unseal

    from tests.fake_rendezvous import FakeRendezvous
    from tests.test_join_request import MEMBER_CAP, RENDEZVOUS, _slot_key

    from starfish_spaces.join_request import (
        PublishSpaceJoinGrantOptions,
        StartSpaceJoinRequestOptions,
        publish_space_join_grant,
        start_space_join_request,
    )

    server = FakeRendezvous()
    session = await start_space_join_request(
        StartSpaceJoinRequestOptions(
            origin="https://myapp.example", rendezvous=RENDEZVOUS, client=server
        )
    )
    await session.publish()
    await publish_space_join_grant(
        PublishSpaceJoinGrantOptions(
            request=session.request,
            code=session.code,
            space_id="sp-1",
            cap=MEMBER_CAP,
            sealer=generate_device_keys(),
            rendezvous=RENDEZVOUS,
            base_hash=server.hash_of(_slot_key(session.code)),
            client=server,
        )
    )
    blob = SealedBlob.from_dict(server.raw(_slot_key(session.code))["sealed"])
    plaintext = _json.loads(
        unseal(blob, session.device["kemPriv"], aad=session.code).decode("utf-8")
    )
    assert plaintext == {
        "v": 1,
        "kind": "starfish-space-join-grant",
        "spaceId": "sp-1",
        "cap": MEMBER_CAP,
    }


async def test_grant_document_uses_exactly_the_agreed_keys():
    from tests.fake_rendezvous import FakeRendezvous
    from tests.test_join_request import MEMBER_CAP, RENDEZVOUS, _slot_key

    from starfish_spaces.join_request import (
        PublishSpaceJoinGrantOptions,
        StartSpaceJoinRequestOptions,
        publish_space_join_grant,
        start_space_join_request,
    )

    server = FakeRendezvous()
    session = await start_space_join_request(
        StartSpaceJoinRequestOptions(
            origin="https://myapp.example", rendezvous=RENDEZVOUS, client=server
        )
    )
    await session.publish()
    await publish_space_join_grant(
        PublishSpaceJoinGrantOptions(
            request=session.request,
            code=session.code,
            space_id="sp-1",
            cap=MEMBER_CAP,
            sealer=generate_device_keys(),
            rendezvous=RENDEZVOUS,
            base_hash=server.hash_of(_slot_key(session.code)),
            client=server,
        )
    )

    doc = server.raw(_slot_key(session.code))
    assert set(doc) == GRANT_KEYS
    assert doc["v"] == 1 and doc["phase"] == "grant"
    # The sealed blob is starfish-keyring's cross-language shape.
    assert set(doc["sealed"]) == {"entry", "ct", "v"}
    assert doc["sealed"]["v"] == 1  # AAD-bound
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", doc["grantedAt"])
