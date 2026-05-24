"""End-to-end regression tests for the chat app, exercising the full v3
library chain in-process (protocol → server → SDK + identities + keyring +
sharing + entitlements + queuing + audit), now with multiple rooms and profiles.

The chat app's FastAPI `server.app` is the instrument: every test drives it
through the real HTTP + cap-cert path via the Python SDK, the same way the
browser frontend does.
"""

from __future__ import annotations

import asyncio
import base64
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from starfish_sdk import StarfishClient, SyncManager, ConflictError
from starfish_sdk.types import StarfishHttpError
from starfish_protocol import stable_stringify, build_revocation_list
from starfish_identities import (
    bootstrap_root_identity,
    mint_device_cap,
    build_pairing_qr,
    parse_pairing_qr,
    assemble_pairing_bundle,
    AssemblePairingBundleOpts,
    install_pairing_bundle,
    provision_device,
    install_provisioned_device,
    generate_device_keys,
    push_pairing_bundle,
    fetch_pairing_bundle,
    clear_pairing_bundle,
    ProvisionDeviceOpts,
)
from starfish_keyring import (
    create_keyring,
    create_keyring_encryptor,
    add_collection_recipient,
    list_recipients,
    Keyring,
)
from starfish_sharing import mint_member_cap, add_member_entry, list_members
from starfish_entitlements import pull_entitlements

import server
from conftest import owner_scope, member_scope, account_scope

ROOM = "general"

# ── Per-room / profile path helpers ───────────────────────────────────────────
def room_pull(r: str = ROOM) -> str:
    return f"/pull/chat/rooms/{r}"


def room_push(r: str = ROOM) -> str:
    return f"/push/chat/rooms/{r}"


def keyring_name(r: str = ROOM) -> str:
    return f"chatkeyring/rooms/{r}"


def members_name(r: str = ROOM) -> str:
    return f"chatmembers/rooms/{r}"


def keyring_pull(r: str = ROOM) -> str:
    return f"/pull/{keyring_name(r)}/_keyring"


def keyring_push(r: str = ROOM) -> str:
    return f"/push/{keyring_name(r)}/_keyring"


def members_pull(r: str = ROOM) -> str:
    return f"/pull/{members_name(r)}/_members"


def members_push(r: str = ROOM) -> str:
    return f"/push/{members_name(r)}/_members"


def profile_pull(uid: str) -> str:
    return f"/pull/user/{uid}/profile"


def profile_push(uid: str) -> str:
    return f"/push/user/{uid}/profile"


def _sub(creds) -> dict[str, str]:
    return {"edPubHex": creds.device["edPub"], "kemPubHex": creds.device["kemPub"]}


def _adder(creds) -> dict[str, str]:
    return {"edPriv": creds.device["edPriv"], "edPub": creds.device["edPub"], "kemPriv": creds.device["kemPriv"]}


def _union_messages(local: dict, remote: dict) -> dict:
    merged = {**remote, **local}
    by_id: dict[str, dict] = {}
    for m in (remote.get("messages") or []) + (local.get("messages") or []):
        by_id[m["id"]] = m
    merged["messages"] = list(by_id.values())
    return merged


def _msg(text: str, creds, name: str) -> dict:
    return {"id": str(uuid.uuid4()), "from": creds.user_id, "name": name, "text": text, "ts": 0}


class Owner:
    def __init__(self, creds, client, encryptor, room):
        self.creds = creds
        self.client = client
        self.encryptor = encryptor
        self.room = room

    def sync(self) -> SyncManager:
        return SyncManager(
            self.client, room_pull(self.room), room_push(self.room),
            encryptor=self.encryptor, on_conflict=_union_messages,
        )


async def _setup_owner(sdk, passphrase: str = "alice-e2e", room: str = ROOM) -> Owner:
    """Idempotent owner setup for a room: keyring + members dir + encrypted empty room."""
    creds = bootstrap_root_identity(passphrase)
    cap = mint_device_cap(creds.device["edPriv"], creds.device["edPub"], _sub(creds), owner_scope())
    client = sdk(cap, creds.device["edPriv"])

    kr = await client.pull(keyring_pull(room))
    if isinstance(kr.data, dict) and kr.data.get("epochs"):
        keyring = Keyring.from_dict(kr.data)
    else:
        keyring, _cek = create_keyring(creds.device["edPriv"], creds.device["edPub"], [creds.device["kemPub"]])
        await client.push(keyring_push(room), keyring.to_dict(), kr.hash or None)

    encryptor = create_keyring_encryptor(
        keyring, creds.device["kemPub"], creds.device["kemPriv"], trusted_adders=[creds.device["edPub"]]
    )

    md = await client.pull(members_pull(room))
    if not isinstance(md.data, dict) or not isinstance(md.data.get("entries"), list):
        await client.push(members_push(room), {"v": 1, "entries": []}, md.hash or None)

    rr = await client.pull(room_pull(room))
    if not (isinstance(rr.data, dict) and rr.data.get("_encrypted")):
        await client.push(room_push(room), encryptor.encrypt({"messages": []}), rr.hash or None)

    return Owner(creds, client, encryptor, room)


# ── Smoke: transport + cap-cert auth through ASGI ─────────────────────────────
async def test_health(http):
    r = await http.get("/health")
    assert r.status_code == 200 and r.json()["ok"] is True


async def test_owner_cap_auth_smoke(sdk):
    creds = bootstrap_root_identity("alice-smoke")
    cap = mint_device_cap(creds.device["edPriv"], creds.device["edPub"], _sub(creds), owner_scope())
    client = sdk(cap, creds.device["edPriv"])
    res = await client.pull(keyring_pull())
    assert res.data == {} or "epochs" in res.data


# ── keyring + sync: owner posts and reads back decrypted ──────────────────────
async def test_owner_posts_and_reads(sdk):
    owner = await _setup_owner(sdk)
    s = owner.sync()
    await s.pull()
    await s.push({**s.data, "messages": [*(s.data.get("messages") or []), _msg("hi", owner.creds, "Alice")]})

    s2 = owner.sync()
    await s2.pull()
    assert "hi" in [m["text"] for m in s2.data["messages"]]


# ── sharing: read/write member can post; both decrypt (N-recipient keyring) ───
async def test_member_readwrite_invite(sdk):
    owner = await _setup_owner(sdk)
    s = owner.sync()
    await s.pull()
    await s.push({**s.data, "messages": [*(s.data.get("messages") or []), _msg("for-bob", owner.creds, "Alice")]})

    bob = bootstrap_root_identity("bob-e2e")
    member_cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        "chat", member_scope(ROOM, True),
    )
    await add_member_entry(owner.client, members_name(), member_cap, label="bob")
    await add_collection_recipient(
        owner.client, keyring_name(),
        {"subKem": bob.device["kemPub"], "userId": bob.user_id, "label": "bob"}, _adder(owner.creds),
        trusted_adders=[owner.creds.device["edPub"]],
    )

    bob_client = sdk(member_cap, bob.device["edPriv"])
    kr = await bob_client.pull(keyring_pull())
    bob_enc = create_keyring_encryptor(
        Keyring.from_dict(kr.data), bob.device["kemPub"], bob.device["kemPriv"],
        trusted_adders=[owner.creds.device["edPub"]],
    )
    bs = SyncManager(bob_client, room_pull(), room_push(), encryptor=bob_enc, on_conflict=_union_messages)
    await bs.pull()
    assert "for-bob" in [m["text"] for m in bs.data["messages"]]  # bob decrypts owner's message
    await bs.push({**bs.data, "messages": [*bs.data["messages"], _msg("bob-reply", bob, "Bob")]})

    members = await list_members(owner.client, members_name())
    assert any(e.get("subUserId") == bob.user_id for e in members)

    os_ = owner.sync()
    await os_.pull()
    assert "bob-reply" in [m["text"] for m in os_.data["messages"]]


# ── sharing: read-only member is denied writes (cap omits the write op) ───────
async def test_member_readonly_cannot_write(sdk):
    owner = await _setup_owner(sdk)
    carol = bootstrap_root_identity("carol-e2e")
    ro_cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": carol.device["edPub"], "kemPubHex": carol.device["kemPub"], "userIdHex": carol.user_id},
        "chat", member_scope(ROOM, False),
    )
    await add_collection_recipient(
        owner.client, keyring_name(),
        {"subKem": carol.device["kemPub"], "userId": carol.user_id, "label": "carol"}, _adder(owner.creds),
        trusted_adders=[owner.creds.device["edPub"]],
    )
    carol_client = sdk(ro_cap, carol.device["edPriv"])
    kr = await carol_client.pull(keyring_pull())
    carol_enc = create_keyring_encryptor(
        Keyring.from_dict(kr.data), carol.device["kemPub"], carol.device["kemPriv"],
        trusted_adders=[owner.creds.device["edPub"]],
    )
    cs = SyncManager(carol_client, room_pull(), room_push(), encryptor=carol_enc, on_conflict=_union_messages)
    await cs.pull()  # read works

    with pytest.raises(StarfishHttpError) as exc:
        await cs.push({**cs.data, "messages": [*cs.data["messages"], _msg("nope", carol, "Carol")]})
    assert exc.value.status == 403


# ── provisioning: a read-only provisioned device reads but cannot write ───────
async def test_provisioned_readonly_device_cannot_write(sdk):
    owner = await _setup_owner(sdk)
    # Owner posts history for the new device to read back.
    s = owner.sync()
    await s.pull()
    await s.push({**s.data, "messages": [*(s.data.get("messages") or []), _msg("history", owner.creds, "Alice")]})

    # Provision a device whose cap is bounded to THIS room, read-only.
    provisioned = provision_device(
        {"edPriv": owner.creds.device["edPriv"], "edPub": owner.creds.device["edPub"]},
        ProvisionDeviceOpts(scope=member_scope(ROOM, False)),
    )
    # A read-only device still needs the CEK to decrypt — its cap only omits write.
    await add_collection_recipient(
        owner.client, keyring_name(),
        {"subKem": provisioned.device_keys["kemPub"], "userId": owner.creds.user_id, "label": "ro-device"},
        _adder(owner.creds), trusted_adders=[owner.creds.device["edPub"]],
    )
    installed = install_provisioned_device(provisioned)
    dev_client = sdk(installed.credentials.cap_cert, provisioned.device_keys["edPriv"])

    # Read works: the device decrypts the owner's history.
    kr = await dev_client.pull(keyring_pull())
    dev_enc = create_keyring_encryptor(
        Keyring.from_dict(kr.data), provisioned.device_keys["kemPub"], provisioned.device_keys["kemPriv"],
        trusted_adders=[owner.creds.device["edPub"]],
    )
    ds = SyncManager(dev_client, room_pull(), room_push(), encryptor=dev_enc, on_conflict=_union_messages)
    await ds.pull()
    assert "history" in [m["text"] for m in ds.data["messages"]]

    # Write is denied: the read-only cap synthesizes no `cap:write:chat` role.
    with pytest.raises(StarfishHttpError) as exc:
        await ds.push({**ds.data, "messages": [*ds.data["messages"], _msg("nope", owner.creds, "RO Device")]})
    assert exc.value.status == 403


# ── provisioning: an expired device cap is rejected by the server ─────────────
async def test_provisioned_expired_cap_is_rejected(sdk):
    owner = await _setup_owner(sdk)
    # Provision a cap that expired long before now (nbf in the past, 1s TTL). We
    # do NOT install it — install verifies the window client-side and would throw
    # first. Handing the expired cap straight to the SDK lets the SERVER's
    # verifyCapCert reject the request.
    past = 1_000_000  # unix seconds, far in the past
    provisioned = provision_device(
        {"edPriv": owner.creds.device["edPriv"], "edPub": owner.creds.device["edPub"]},
        ProvisionDeviceOpts(scope=owner_scope(), nbf=past, ttl_sec=1),
    )
    dev_client = sdk(provisioned.bundle.cap_cert, provisioned.device_keys["edPriv"])
    with pytest.raises(StarfishHttpError) as exc:
        await dev_client.pull(room_pull())
    assert exc.value.status == 401


# ── QR-in / auto-return: anonymous rendezvous round-trip through the server ───
async def test_qr_in_rendezvous_pairing_roundtrip(sdk):
    owner = await _setup_owner(sdk)
    # Owner posts history for the new device to read back.
    s = owner.sync()
    await s.pull()
    await s.push({**s.data, "messages": [*(s.data.get("messages") or []), _msg("rzhistory", owner.creds, "Alice")]})

    # New device (no camera): generate keys + its pairing QR.
    device = generate_device_keys()
    qr = build_pairing_qr(device["edPub"], device["kemPub"], owner_scope())
    parsed = parse_pairing_qr(qr)

    # Root "scans" (parses), assembles the bundle, adds the device to the keyring,
    # and PUSHES the bundle to the public rendezvous slot via an ANONYMOUS client.
    bundle = assemble_pairing_bundle(
        {"edPriv": owner.creds.device["edPriv"], "edPub": owner.creds.device["edPub"]}, parsed, {},
        AssemblePairingBundleOpts(granted_scope=parsed.requested_scope),
    )
    await add_collection_recipient(
        owner.client, keyring_name(),
        {"subKem": device["kemPub"], "userId": owner.creds.user_id, "label": "qr-device"},
        _adder(owner.creds), trusted_adders=[owner.creds.device["edPub"]],
    )
    await push_pairing_bundle(sdk(), parsed.qr_nonce, bundle)  # sdk() with no cap = anonymous

    # New device: a SINGLE anonymous fetch retrieves + installs the bundle,
    # pinning the session nonce and the (known) root identity.
    anon = sdk()
    fetched = await fetch_pairing_bundle(anon, parsed.qr_nonce)
    assert fetched is not None
    installed = install_pairing_bundle(
        fetched, device,
        expected_qr_nonce=parsed.qr_nonce,
        expected_root_ed_pub=owner.creds.root_ed_pub,
    )

    # The paired device can now read the room (decrypts the owner's history).
    dev_client = sdk(installed.credentials.cap_cert, device["edPriv"])
    kr = await dev_client.pull(keyring_pull())
    dev_enc = create_keyring_encryptor(
        Keyring.from_dict(kr.data), device["kemPub"], device["kemPriv"],
        trusted_adders=[owner.creds.device["edPub"]],
    )
    ds = SyncManager(dev_client, room_pull(), room_push(), encryptor=dev_enc, on_conflict=_union_messages)
    await ds.pull()
    assert "rzhistory" in [m["text"] for m in ds.data["messages"]]

    # One-shot: after install the new device clears the slot; a later fetch is empty.
    await clear_pairing_bundle(anon, parsed.qr_nonce)
    assert await fetch_pairing_bundle(sdk(), parsed.qr_nonce) is None


# ── QR-in: a bundle from a DIFFERENT root is rejected when the root is pinned ──
async def test_qr_in_rendezvous_rejects_wrong_root(sdk):
    owner = await _setup_owner(sdk)
    attacker = bootstrap_root_identity("attacker-rz")
    device = generate_device_keys()
    qr = build_pairing_qr(device["edPub"], device["kemPub"], owner_scope())
    parsed = parse_pairing_qr(qr)
    # The ATTACKER's root answers the rendezvous with its own validly-signed bundle.
    bundle = assemble_pairing_bundle(
        {"edPriv": attacker.device["edPriv"], "edPub": attacker.device["edPub"]}, parsed, {},
        AssemblePairingBundleOpts(granted_scope=parsed.requested_scope),
    )
    await push_pairing_bundle(sdk(), parsed.qr_nonce, bundle)
    fetched = await fetch_pairing_bundle(sdk(), parsed.qr_nonce)
    assert fetched is not None
    # The new device pins ITS owner's root → the attacker's bundle is rejected.
    with pytest.raises(ValueError, match="root identity"):
        install_pairing_bundle(
            fetched, device,
            expected_qr_nonce=parsed.qr_nonce,
            expected_root_ed_pub=owner.creds.root_ed_pub,
        )


# ── entitlements: client-side paid-feature unlock via pullEntitlements ────────
async def test_entitlements_premium_unlock(sdk, http):
    creds = bootstrap_root_identity("dave-e2e")
    acc_cap = mint_device_cap(creds.device["edPriv"], creds.device["edPub"], _sub(creds), account_scope(creds.user_id))
    client = sdk(acc_cap, creds.device["edPriv"])

    assert await pull_entitlements(client, creds.user_id) == []
    await http.post("/demo/grant", json={"userId": creds.user_id})
    assert "premium" in await pull_entitlements(client, creds.user_id)
    await http.post("/demo/revoke", json={"userId": creds.user_id})
    assert await pull_entitlements(client, creds.user_id) == []


# ── profile: public read, owner-restricted write ─────────────────────────────
async def test_profile_public_read_and_owner_write(sdk):
    creds = bootstrap_root_identity("profile-owner")
    acc_cap = mint_device_cap(creds.device["edPriv"], creds.device["edPub"], _sub(creds), account_scope(creds.user_id))
    acc = sdk(acc_cap, creds.device["edPriv"])  # has cap:write:profile + own identity
    await acc.push(profile_push(creds.user_id), {"v": 1, "pseudo": "Alice the Owner"}, None)

    anon = sdk()  # no cap — public read
    res = await anon.pull(profile_pull(creds.user_id))
    assert res.data["pseudo"] == "Alice the Owner"


async def test_member_cannot_write_profile(sdk):
    owner = await _setup_owner(sdk)
    member = bootstrap_root_identity("prof-member")
    cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": member.device["edPub"], "kemPubHex": member.device["kemPub"], "userIdHex": member.user_id},
        "chat", member_scope(ROOM, True),  # chat-only cap, no profile path
    )
    m_client = sdk(cap, member.device["edPriv"])
    with pytest.raises(StarfishHttpError) as exc:
        await m_client.push(profile_push(member.user_id), {"v": 1, "pseudo": "hax"}, None)
    assert exc.value.status in (401, 403)


async def test_profile_identity_binding(sdk):
    alice = bootstrap_root_identity("prof-alice")
    bob = bootstrap_root_identity("prof-bob")
    acc_cap = mint_device_cap(alice.device["edPriv"], alice.device["edPub"], _sub(alice), account_scope(alice.user_id))
    acc = sdk(acc_cap, alice.device["edPriv"])  # may write user/<alice>/profile only
    with pytest.raises(StarfishHttpError) as exc:
        await acc.push(profile_push(bob.user_id), {"v": 1, "pseudo": "spoofed"}, None)
    assert exc.value.status == 403


# ── profile: only the MAIN (root) device may edit it ──────────────────────────
# The profile collection's writeRoles=["device:root"] (the synthesized
# root-device role) gates writes ON TOP of cap scope. Only a self-signed root
# device cap (iss === sub) earns device:root. A one-way-provisioned device gets
# a DELEGATED cap (iss != sub); even when its scope explicitly covers the
# profile path (so the old cap:write:profile rule WOULD have let it through), it
# is now rejected for lacking device:root — while reads stay public.
async def test_only_main_device_can_write_profile(sdk):
    creds = bootstrap_root_identity("prof-main")
    # The app writes a profile via the account-scoped cap (covers user/<id>/profile).
    # It is self-signed (iss === sub) → also holds device:root → write allowed.
    root_cap = mint_device_cap(
        creds.device["edPriv"], creds.device["edPub"], _sub(creds), account_scope(creds.user_id)
    )
    root = sdk(root_cap, creds.device["edPriv"])
    await root.push(profile_push(creds.user_id), {"v": 1, "pseudo": "Main"}, None)

    # Provision a device whose scope DOES cover the profile path — so only the
    # device:root gate, not scope, can stop it. Its cap is delegated (iss=root,
    # sub=device) → no device:root → profile write 403.
    provisioned = provision_device(
        {"edPriv": creds.device["edPriv"], "edPub": creds.device["edPub"]},
        ProvisionDeviceOpts(scope=account_scope(creds.user_id)),
    )
    installed = install_provisioned_device(provisioned)
    dev_client = sdk(installed.credentials.cap_cert, provisioned.device_keys["edPriv"])
    with pytest.raises(StarfishHttpError) as exc:
        await dev_client.push(profile_push(creds.user_id), {"v": 1, "pseudo": "clone wins"}, None)
    assert exc.value.status == 403

    # Reads remain public, and the main device's pseudo is unchanged.
    anon = sdk()
    res = await anon.pull(profile_pull(creds.user_id))
    assert res.data["pseudo"] == "Main"


# ── multiple rooms: a member of one room cannot reach another ─────────────────
async def test_room_isolation(sdk):
    owner = await _setup_owner(sdk, room="general")
    await _setup_owner(sdk, room="private")  # same owner creates a second room
    member = bootstrap_root_identity("iso-member")
    cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": member.device["edPub"], "kemPubHex": member.device["kemPub"], "userIdHex": member.user_id},
        "chat", member_scope("general", True),  # scoped to "general" only
    )
    m_client = sdk(cap, member.device["edPriv"])
    await m_client.pull(room_pull("general"))  # allowed
    with pytest.raises(StarfishHttpError) as exc:
        await m_client.pull(room_pull("private"))  # outside scope.paths
    assert exc.value.status == 403


# ── audit: every push is recorded ─────────────────────────────────────────────
async def test_audit_records_pushes(sdk, http):
    owner = await _setup_owner(sdk)
    s = owner.sync()
    await s.pull()
    await s.push({**s.data, "messages": [*(s.data.get("messages") or []), _msg("audit-me", owner.creds, "Alice")]})

    rows = (await http.get("/audit")).json()
    # The audit trail now records denials too (success=False), so filter to the
    # successful chat pushes when asserting the happy-path record.
    ok_chat_pushes = [
        r for r in rows
        if r["action"] == "push" and r["collection"] == "chat" and r["statusCode"] == 200
    ]
    assert ok_chat_pushes and all(r["success"] is True for r in ok_chat_pushes)
    assert any(r["identity"] == owner.creds.user_id for r in ok_chat_pushes)


# ── queuing: a chat push fans out a change event carrying the room id ─────────
async def test_queuing_publishes_event(sdk):
    owner = await _setup_owner(sdk)
    q: asyncio.Queue[str] = asyncio.Queue()
    server.sse_subscribers.add(q)
    try:
        s = owner.sync()
        await s.pull()
        await s.push({**s.data, "messages": [*(s.data.get("messages") or []), _msg("ping", owner.creds, "Alice")]})
        event = await asyncio.wait_for(q.get(), timeout=2.0)
        import json
        payload = json.loads(event)
        assert payload["collection"] == "chat" and "hash" in payload
        assert payload.get("params", {}).get("roomId") == ROOM
    finally:
        server.sse_subscribers.discard(q)


# ── auth boundary / cap scope / identity isolation ────────────────────────────
async def test_anonymous_read_denied(sdk):
    await _setup_owner(sdk)
    anon = sdk()
    with pytest.raises(StarfishHttpError) as exc:
        await anon.pull(room_pull())
    assert exc.value.status in (401, 403)


async def test_path_outside_scope_denied(sdk):
    owner = await _setup_owner(sdk)
    bob = bootstrap_root_identity("bob-scope")
    cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        "chat", member_scope(ROOM, True),
    )
    bob_client = sdk(cap, bob.device["edPriv"])
    with pytest.raises(StarfishHttpError) as exc:
        await bob_client.pull(members_pull())  # member dir not in scope.paths
    assert exc.value.status == 403


async def test_identity_isolation(sdk):
    alice = bootstrap_root_identity("alice-iso")
    bob = bootstrap_root_identity("bob-iso")
    cap = mint_device_cap(alice.device["edPriv"], alice.device["edPub"], _sub(alice), account_scope(alice.user_id))
    client = sdk(cap, alice.device["edPriv"])
    with pytest.raises(StarfishHttpError) as exc:
        await client.pull(f"/pull/users/{bob.user_id}/entitlements")
    assert exc.value.status == 403


# ── revocation: member + device caps ──────────────────────────────────────────
def _sign_revocation_list(iss_pub: str, iss_priv: str, revoked: list[dict], generation: int) -> dict:
    """Sign a revocation list via the lib `build_revocation_list` (no hand-rolled
    signing). Adds the canonical `v` + `issUserId` fields the real frontend emits,
    eliminating the prior format drift between this test helper and the library.
    """
    return build_revocation_list(iss_pub, iss_priv, generation, revoked=revoked)


async def test_revoked_member_cap_denied(sdk):
    owner = await _setup_owner(sdk)
    bob = bootstrap_root_identity("bob-revoke")
    cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        "chat", member_scope(ROOM, True),
    )
    bob_client = sdk(cap, bob.device["edPriv"])
    await bob_client.pull(room_pull())  # works before revocation

    rev_list = _sign_revocation_list(
        owner.creds.device["edPub"], owner.creds.device["edPriv"],
        [{"sub": cap["sub"], "nonce": cap["nonce"]}], generation=1,
    )
    assert server.revocation_store.accept_list(rev_list)["ok"] is True

    with pytest.raises(StarfishHttpError) as exc:
        await bob_client.pull(room_pull())
    assert exc.value.status == 401


async def test_revoked_device_cap_denied(sdk):
    await _setup_owner(sdk)
    root = bootstrap_root_identity("device-rev-root")
    dev = bootstrap_root_identity("device-rev-keys").device
    parsed = parse_pairing_qr(build_pairing_qr(dev["edPub"], dev["kemPub"], owner_scope()))
    bundle = assemble_pairing_bundle(
        {"edPriv": root.device["edPriv"], "edPub": root.device["edPub"]}, parsed, {},
        AssemblePairingBundleOpts(granted_scope=parsed.requested_scope),
    )
    device_cap = install_pairing_bundle(bundle, dev).credentials.cap_cert
    assert device_cap["kind"] == "device"

    dev_client = sdk(device_cap, dev["edPriv"])
    await dev_client.pull(room_pull())  # device cap authenticates before revocation

    rev_list = _sign_revocation_list(
        root.device["edPub"], root.device["edPriv"],
        [{"sub": device_cap["sub"], "nonce": device_cap["nonce"]}], generation=1,
    )
    assert server.revocation_store.accept_list(rev_list)["ok"] is True

    with pytest.raises(StarfishHttpError) as exc:
        await dev_client.pull(room_pull())
    assert exc.value.status == 401


# ── sync: concurrent writers' messages are merged (no lost write) ─────────────
async def test_conflict_resolution_merges(sdk):
    owner = await _setup_owner(sdk)
    s1, s2 = owner.sync(), owner.sync()
    await s1.pull()
    await s2.pull()
    a, b = "concurrent-A-" + uuid.uuid4().hex[:6], "concurrent-B-" + uuid.uuid4().hex[:6]
    await s1.push({**s1.data, "messages": [*(s1.data.get("messages") or []), _msg(a, owner.creds, "A")]})
    await s2.push({**s2.data, "messages": [*(s2.data.get("messages") or []), _msg(b, owner.creds, "B")]})  # 409 → retry+merge

    s3 = owner.sync()
    await s3.pull()
    texts = [m["text"] for m in s3.data["messages"]]
    assert a in texts and b in texts


async def test_conflict_audited_as_failure(sdk, http):
    owner = await _setup_owner(sdk)
    room = await owner.client.pull(room_pull())
    with pytest.raises(ConflictError):
        await owner.client.push(room_push(), owner.encryptor.encrypt({"messages": []}), "0" * 64)
    rows = (await http.get("/audit")).json()
    assert any(r["collection"] == "chat" and r["success"] is False for r in rows)
    assert room.hash


# ── keyring: recipients are listed; a non-recipient cannot decrypt ────────────
async def test_keyring_lists_recipients(sdk):
    owner = await _setup_owner(sdk)
    listing = await list_recipients(owner.client, keyring_name(), trusted_adders=[owner.creds.device["edPub"]])
    assert listing["epoch"] >= 1 and len(listing["recipients"]) >= 1


async def test_non_recipient_cannot_decrypt(sdk):
    owner = await _setup_owner(sdk)
    s = owner.sync()
    await s.pull()
    await s.push({**s.data, "messages": [*(s.data.get("messages") or []), _msg("secret", owner.creds, "Alice")]})

    mallory = bootstrap_root_identity("mallory-e2e")
    cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": mallory.device["edPub"], "kemPubHex": mallory.device["kemPub"], "userIdHex": mallory.user_id},
        "chat", member_scope(ROOM, True),
    )
    m_client = sdk(cap, mallory.device["edPriv"])
    kr = await m_client.pull(keyring_pull())  # cap allows reading the keyring
    with pytest.raises(Exception):
        enc = create_keyring_encryptor(
            Keyring.from_dict(kr.data), mallory.device["kemPub"], mallory.device["kemPriv"],
            trusted_adders=[owner.creds.device["edPub"]],
        )
        ms = SyncManager(m_client, room_pull(), room_push(), encryptor=enc, on_conflict=_union_messages)
        await ms.pull()


# ── identities: pair a second device → same userId, can decrypt ───────────────
async def test_pairing_second_device(sdk):
    owner = await _setup_owner(sdk)
    dev = bootstrap_root_identity("paired-device-keys").device
    parsed = parse_pairing_qr(build_pairing_qr(dev["edPub"], dev["kemPub"], owner_scope()))
    bundle = assemble_pairing_bundle(
        {"edPriv": owner.creds.device["edPriv"], "edPub": owner.creds.device["edPub"]}, parsed, {},
        AssemblePairingBundleOpts(granted_scope=parsed.requested_scope),
    )
    installed = install_pairing_bundle(bundle, dev)
    assert installed.credentials.user_id == owner.creds.user_id

    await add_collection_recipient(
        owner.client, keyring_name(),
        {"subKem": dev["kemPub"], "userId": owner.creds.user_id, "label": "device-2"}, _adder(owner.creds),
        trusted_adders=[owner.creds.device["edPub"]],
    )
    dev_client = sdk(installed.credentials.cap_cert, dev["edPriv"])
    kr = await dev_client.pull(keyring_pull())
    dev_enc = create_keyring_encryptor(
        Keyring.from_dict(kr.data), dev["kemPub"], dev["kemPriv"],
        trusted_adders=[owner.creds.device["edPub"]],
    )
    ds = SyncManager(dev_client, room_pull(), room_push(), encryptor=dev_enc, on_conflict=_union_messages)
    await ds.pull()
    assert isinstance(ds.data.get("messages"), list)
