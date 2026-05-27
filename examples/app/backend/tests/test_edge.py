"""Adversarial / edge-case suite for the chat app — companion to ``test_e2e.py``.

Where ``test_e2e.py`` walks the *happy* flows (and a handful of negative paths),
this file deliberately sets up *complicated* and *hostile* situations to probe
the security boundaries of the full v3 library chain as the app wires it:

  • cap-cert integrity      — a stolen cap cannot be edited to widen scope or
                              extend its lifetime; a forged issuer is rejected
  • request freshness       — a captured request cannot be replayed (nonce) and a
                              stale-clock request is refused
  • revocation robustness   — a non-issuer cannot revoke someone else's cap, and a
                              stale-generation list cannot un-revoke
  • keyring forward secrecy — a removed recipient keeps old plaintext but cannot
                              read anything sealed after the epoch rotates
  • trust-model boundaries  — what the server does NOT gate (writes are authorized
                              by cap *scope*, not by "issuer is the room owner"),
                              so confidentiality rests on the keyring while
                              write-integrity does not. These tests PIN current
                              behavior; the module docstring of ``server.py`` and
                              ``TESTING.md`` describe the intended model.
  • body-size limits        — the pre-auth guard caps writes before the body is read

Every test drives the in-process FastAPI ``server.app`` through the real HTTP +
cap-cert path via the Python SDK, exactly like ``test_e2e.py``. Helpers and the
``sdk`` / ``http`` fixtures are reused from the e2e module / conftest so this file
stays a thin layer of adversarial scenarios on top of the same harness.

Destructive scenarios (room/keyring overwrite, epoch rotation) each use their own
room id so they cannot perturb the shared ``general`` room that the e2e suite
builds up — test ordering stays irrelevant.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import json
import time
from urllib.parse import quote

import httpx
import pytest

from starfish_sdk import SyncManager, ConflictError
from starfish_sdk.types import StarfishHttpError
from starfish_protocol import stable_stringify
from starfish_protocol.request_signing import sign_request
from starfish_identities import (
    bootstrap_root_identity,
    mint_device_cap,
    build_pairing_qr,
    parse_pairing_qr,
    assemble_pairing_bundle,
    AssemblePairingBundleOpts,
    install_pairing_bundle,
    generate_device_keys,
    push_pairing_bundle,
    fetch_pairing_bundle,
    clear_pairing_bundle,
    provision_device,
    ProvisionDeviceOpts,
)
from starfish_keyring import (
    create_keyring,
    create_keyring_encryptor,
    add_collection_recipient,
    remove_recipient,
    rotate_epoch,
    list_recipients,
    Keyring,
)
from starfish_sharing import mint_member_cap, add_member_entry, list_members, evict_member
from starfish_entitlements import pull_entitlements

import server
from conftest import BASE_URL, owner_scope, member_scope, account_scope

# Reuse the e2e helpers verbatim rather than redefining them.
from test_e2e import (
    ROOM,
    _setup_owner,
    _sub,
    _adder,
    _msg,
    _sign_revocation_list,
    _union_messages,
    room_pull,
    room_push,
    keyring_pull,
    keyring_push,
    keyring_name,
    members_name,
    members_pull,
    members_push,
)


# ── cap-cert integrity: a cap is signed over ALL its fields ───────────────────
# The cap-cert is an Ed25519-signed bearer token. Editing any field after issue
# (to grant yourself more) invalidates the signature, so the server rejects it
# 401 before scope is ever consulted. These prove the bearer token cannot be
# upgraded by its holder.
async def test_tampered_scope_widening_rejected(sdk):
    """A read-only member edits their cap to add `write` + a wildcard path → 401."""
    owner = await _setup_owner(sdk)
    bob = bootstrap_root_identity("edge-tamper-scope")
    ro_cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        "chat", member_scope(ROOM, False),  # read-only, single room
    )
    tampered = copy.deepcopy(ro_cap)
    tampered["scope"]["ops"] = ["read", "list", "write"]   # grant self write
    tampered["scope"]["paths"] = ["chat/rooms/**"]          # widen to every room

    client = sdk(tampered, bob.device["edPriv"])
    with pytest.raises(StarfishHttpError) as exc:
        await client.pull(room_pull())
    assert exc.value.status == 401  # bad-signature, not 403 — caught before scope check


async def test_tampered_expiry_extension_rejected(sdk):
    """Pushing a cap's `exp` far into the future to outlive its grant → 401."""
    owner = await _setup_owner(sdk)
    bob = bootstrap_root_identity("edge-tamper-exp")
    cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        "chat", member_scope(ROOM, True),
    )
    tampered = copy.deepcopy(cap)
    tampered["exp"] = cap["exp"] + 100 * 365 * 24 * 3600  # +100 years

    client = sdk(tampered, bob.device["edPriv"])
    with pytest.raises(StarfishHttpError) as exc:
        await client.pull(room_pull())
    assert exc.value.status == 401


async def test_forged_issuer_cap_rejected(sdk):
    """Mallory mints a cap that NAMES the owner as issuer but signs it herself → 401.

    The cap's `iss` is the owner's Ed25519 pubkey, but the signature is made with
    Mallory's private key, so it cannot verify against `iss`. A holder cannot
    fabricate an owner-issued grant without the owner's signing key.
    """
    owner = await _setup_owner(sdk)
    mallory = bootstrap_root_identity("edge-forge-iss")
    bob = bootstrap_root_identity("edge-forge-sub")
    forged = mint_member_cap(
        mallory.device["edPriv"],          # SIGNED BY mallory …
        owner.creds.device["edPub"],       # … but claims the owner as issuer
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        "chat", member_scope(ROOM, True),
    )
    client = sdk(forged, bob.device["edPriv"])
    with pytest.raises(StarfishHttpError) as exc:
        await client.pull(room_pull())
    assert exc.value.status == 401


# ── request freshness: per-request signature + nonce + clock skew ─────────────
# These craft the signed HTTP request by hand (the SDK always picks a fresh nonce
# and the current time, so it cannot express these attacks). The host folded into
# the signature must be `testserver` — what the ASGI transport presents and what
# the server reconstructs — or the signature would fail for the wrong reason.
def _signed_get_headers(
    cap: dict, dev_ed_priv_hex: str, path: str, *,
    nonce: bytes | None = None, ts: int | None = None, host: str = "testserver",
) -> dict[str, str]:
    """Mirror of the SDK's `_auth_headers` for a GET (empty body), but with a
    caller-controlled nonce/ts so a request can be replayed or back-dated."""
    sig = sign_request("GET", path, b"", dev_ed_priv_hex, host=host, ts=ts, nonce=nonce)
    cap_b64 = base64.b64encode(stable_stringify(cap).encode("utf-8")).decode("ascii")
    return {
        "Authorization": f"Cap {cap_b64}",
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": str(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
        "Accept": "application/json",
    }


async def test_replayed_request_nonce_rejected(sdk, http):
    """A byte-identical signed request sent twice: first 200, replay 401.

    Bit-for-bit replay is a valid signature — the nonce cache is what stops it.
    """
    await _setup_owner(sdk)
    carol = bootstrap_root_identity("edge-replay")
    cap = mint_device_cap(
        carol.device["edPriv"], carol.device["edPub"], _sub(carol), member_scope(ROOM, False),
    )
    path = room_pull()
    headers = _signed_get_headers(cap, carol.device["edPriv"], path, nonce=b"edge-replay-nnce")

    first = await http.get(path, headers=headers)
    replay = await http.get(path, headers=headers)  # same nonce + sig + ts
    assert first.status_code == 200
    assert replay.status_code == 401


async def test_stale_timestamp_rejected(sdk, http):
    """A request signed with a timestamp 10 min in the past (beyond the 5-min skew) → 401."""
    await _setup_owner(sdk)
    carol = bootstrap_root_identity("edge-stale-ts")
    cap = mint_device_cap(
        carol.device["edPriv"], carol.device["edPub"], _sub(carol), member_scope(ROOM, False),
    )
    path = room_pull()
    stale_ts = int(time.time() * 1000) - 10 * 60 * 1000
    headers = _signed_get_headers(cap, carol.device["edPriv"], path, ts=stale_ts)

    resp = await http.get(path, headers=headers)
    assert resp.status_code == 401


# ── revocation robustness ──────────────────────────────────────────────────────
async def test_revocation_by_non_issuer_does_not_revoke(sdk, http):
    """A revocation list signed by someone OTHER than the cap's issuer is harmless.

    Mallory submits a well-formed, validly-signed list that names the owner-issued
    member cap by (sub, nonce). The store accepts it (it is a valid list *for
    Mallory's issuer key*), but the resolver only consults the revocation index of
    the cap's actual issuer (the owner), so the targeted cap keeps working. You can
    only revoke caps you issued.
    """
    owner = await _setup_owner(sdk)
    bob = bootstrap_root_identity("edge-rev-nonissuer")
    cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        "chat", member_scope(ROOM, True),
    )
    bob_client = sdk(cap, bob.device["edPriv"])
    await bob_client.pull(room_pull())  # works

    mallory = bootstrap_root_identity("edge-rev-mallory")
    forged_list = _sign_revocation_list(
        mallory.device["edPub"], mallory.device["edPriv"],   # signed by Mallory
        [{"sub": cap["sub"], "nonce": cap["nonce"]}], generation=1,
    )
    accepted = (await http.post("/revocations", json=forged_list)).json()
    assert accepted["ok"] is True  # the list itself is valid for Mallory's key

    await bob_client.pull(room_pull())  # still works: owner never revoked this cap


async def test_stale_generation_cannot_unrevoke(sdk, http):
    """A lower-generation revocation list cannot resurrect a revoked cap.

    The issuer revokes Bob at generation 2. A later list at generation 1 with an
    empty `revoked` set — which WOULD clear the revocation if accepted — is refused
    `stale-generation`, and Bob stays 401. A dedicated issuer identity keeps this
    independent of the session-shared revocation store's per-issuer generation.
    """
    await _setup_owner(sdk)  # ensure the room exists to read
    issuer = bootstrap_root_identity("edge-rev-stalegen-issuer")
    bob = bootstrap_root_identity("edge-rev-stalegen")
    cap = mint_member_cap(
        issuer.device["edPriv"], issuer.device["edPub"],
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        "chat", member_scope(ROOM, True),
    )
    bob_client = sdk(cap, bob.device["edPriv"])
    await bob_client.pull(room_pull())

    rev = _sign_revocation_list(
        issuer.device["edPub"], issuer.device["edPriv"],
        [{"sub": cap["sub"], "nonce": cap["nonce"]}], generation=2,
    )
    assert (await http.post("/revocations", json=rev)).status_code == 200
    with pytest.raises(StarfishHttpError) as exc:
        await bob_client.pull(room_pull())
    assert exc.value.status == 401

    # Attempt to "un-revoke" with an older generation + empty list → refused.
    stale = _sign_revocation_list(
        issuer.device["edPub"], issuer.device["edPriv"], [], generation=1,
    )
    resp = await http.post("/revocations", json=stale)
    assert resp.status_code == 400 and resp.json()["reason"] == "stale-generation"

    with pytest.raises(StarfishHttpError) as exc:
        await bob_client.pull(room_pull())
    assert exc.value.status == 401  # still revoked


# ── keyring forward secrecy: removing a recipient rotates the epoch ───────────
async def test_removed_recipient_cannot_decrypt_after_rotation(sdk):
    """A removed recipient keeps old plaintext but cannot read post-rotation writes.

    Dave is added to the keyring, reads a message, then removed. `remove_recipient`
    rotates to a fresh epoch + CEK that Dave was never given. His member cap is NOT
    revoked, so he can still PULL the ciphertext — but decrypting the message the
    owner sealed under the new epoch fails. Confidentiality of new content survives
    a removed-but-not-revoked reader.
    """
    owner = await _setup_owner(sdk, room="edge-fs")
    dave = bootstrap_root_identity("edge-fs-dave")
    await add_collection_recipient(
        owner.client, keyring_name("edge-fs"),
        {"subKem": dave.device["kemPub"], "userId": dave.user_id, "label": "dave"}, _adder(owner.creds),
        trusted_adders=[owner.creds.device["edPub"]],
    )
    dave_cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": dave.device["edPub"], "kemPubHex": dave.device["kemPub"], "userIdHex": dave.user_id},
        "chat", member_scope("edge-fs", True),
    )
    dave_client = sdk(dave_cap, dave.device["edPriv"])
    kr = await dave_client.pull(keyring_pull("edge-fs"))
    dave_enc = create_keyring_encryptor(
        Keyring.from_dict(kr.data), dave.device["kemPub"], dave.device["kemPriv"],
        trusted_adders=[owner.creds.device["edPub"]],
    )

    # Owner posts; Dave (current recipient) decrypts it.
    s = owner.sync()
    await s.pull()
    await s.push({**s.data, "messages": [*(s.data.get("messages") or []), _msg("before-remove", owner.creds, "Alice")]})
    ds = SyncManager(dave_client, room_pull("edge-fs"), room_push("edge-fs"), encryptor=dave_enc, on_conflict=_union_messages)
    await ds.pull()
    assert "before-remove" in [m["text"] for m in ds.data["messages"]]

    # Owner removes Dave → epoch rotates, fresh CEK. Owner re-encrypts under it.
    result = await remove_recipient(
        owner.client, keyring_name("edge-fs"), [dave.device["kemPub"]], _adder(owner.creds),
        trusted_adders=[owner.creds.device["edPub"]],
    )
    assert result["newEpoch"] >= 2
    kr2 = Keyring.from_dict((await owner.client.pull(keyring_pull("edge-fs"))).data)
    owner_enc2 = create_keyring_encryptor(
        kr2, owner.creds.device["kemPub"], owner.creds.device["kemPriv"],
        trusted_adders=[owner.creds.device["edPub"]],
    )
    s2 = owner.sync()
    await s2.pull()
    await owner.client.push(
        room_push("edge-fs"),
        owner_enc2.encrypt({**s2.data, "messages": [*s2.data["messages"], _msg("after-remove-secret", owner.creds, "Alice")]}),
        (await owner.client.pull(room_pull("edge-fs"))).hash,
    )

    # Dave's cap still authorizes the read (not revoked) — the pull succeeds …
    after = await dave_client.pull(room_pull("edge-fs"))
    # … but his stale encryptor cannot decrypt the new-epoch ciphertext.
    with pytest.raises(Exception):
        dave_enc.decrypt(after.data)


# ── trust-model boundaries: what the server does NOT gate ─────────────────────
# The cap-resolver authorizes a chat request purely on a validly-signed cap whose
# scope covers the path — it does NOT check that the issuer is the room's owner.
# `mint_member_cap` forbids a self-issued member cap (`member-self`), but
# `mint_device_cap` has no such guard, so a stranger can self-sign a root device
# cap (iss == sub) scoped to a room. The keyring (encryption) protects
# confidentiality; it does not protect write-integrity / availability. The three
# tests below PIN this behavior so a future tightening (e.g. owner-gated writes)
# surfaces here as an intended change rather than a silent regression.
async def test_stranger_self_signed_cap_reads_ciphertext_but_cannot_decrypt(sdk):
    """A stranger's self-signed device cap reads the room blob (200) but can't decrypt.

    Authorization to fetch the ciphertext is not owner-gated — yet without a CEK
    from the keyring the bytes stay opaque. This is the confidentiality half of the
    model: read access ≠ plaintext access.
    """
    owner = await _setup_owner(sdk, room="edge-confidential")
    s = owner.sync()
    await s.pull()
    await s.push({**s.data, "messages": [*(s.data.get("messages") or []), _msg("top-secret", owner.creds, "Alice")]})

    stranger = bootstrap_root_identity("edge-stranger-read")
    self_cap = mint_device_cap(
        stranger.device["edPriv"], stranger.device["edPub"], _sub(stranger), member_scope("edge-confidential", False),
    )
    sclient = sdk(self_cap, stranger.device["edPriv"])
    res = await sclient.pull(room_pull("edge-confidential"))  # 200 — not owner-gated
    assert isinstance(res.data, dict) and res.data.get("_encrypted")

    # The stranger is not a keyring recipient, so building/using a decryptor fails.
    kr = await sclient.pull(keyring_pull("edge-confidential"))
    with pytest.raises(Exception):
        enc = create_keyring_encryptor(
            Keyring.from_dict(kr.data), stranger.device["kemPub"], stranger.device["kemPriv"],
            trusted_adders=[owner.creds.device["edPub"]],
        )
        enc.decrypt(res.data)


async def test_stranger_self_signed_cap_cannot_overwrite_room(sdk):
    """A stranger's self-signed WRITE-scoped device cap CANNOT clobber the room → 403.

    Room-document writes are membership-bound (Level 3): the `chat` collection's write
    role is `chat:owner` / `chat:member`, synthesized by the enricher only for the room
    owner or a writer listed in the member directory. A self-signed stranger holding a
    chat-scoped cap is neither, so the overwrite is refused — closing the clobber /
    availability gap. (The stranger can still READ the ciphertext; confidentiality
    rests on the keyring as before.)
    """
    owner = await _setup_owner(sdk, room="edge-clobber")
    s = owner.sync()
    await s.pull()
    await s.push({**s.data, "messages": [*(s.data.get("messages") or []), _msg("genuine", owner.creds, "Alice")]})

    stranger = bootstrap_root_identity("edge-clobber-stranger")
    self_cap = mint_device_cap(
        stranger.device["edPriv"], stranger.device["edPub"], _sub(stranger), member_scope("edge-clobber", True),
    )
    sclient = sdk(self_cap, stranger.device["edPriv"])

    # Encrypt under the stranger's OWN keyring (just to produce a well-formed body).
    skr, _cek = create_keyring(stranger.device["edPriv"], stranger.device["edPub"], [stranger.device["kemPub"]])
    senc = create_keyring_encryptor(
        skr, stranger.device["kemPub"], stranger.device["kemPriv"],
        trusted_adders=[stranger.device["edPub"]],
    )
    base_hash = (await sclient.pull(room_pull("edge-clobber"))).hash  # read is allowed
    with pytest.raises(StarfishHttpError) as exc:
        await sclient.push(room_push("edge-clobber"), senc.encrypt({"messages": [{"id": "x", "text": "clobbered"}]}), base_hash)
    assert exc.value.status == 403

    # The owner's content is intact — still decryptable by the owner.
    intact = await owner.client.pull(room_pull("edge-clobber"))
    assert "genuine" in [m["text"] for m in owner.encryptor.decrypt(intact.data)["messages"]]


async def test_member_cannot_overwrite_shared_keyring(sdk):
    """A read/write member CANNOT overwrite the shared keyring → 403 (owner-only).

    The keyring collection's write role is now `chat:owner`, granted by the
    owner-role enricher only to the room owner. A read/write member can still READ
    the keyring (to decrypt) but a push is refused, so it cannot evict recipients or
    rotate the room out from under the owner.
    """
    owner = await _setup_owner(sdk, room="edge-keyring")
    bob = bootstrap_root_identity("edge-keyring-bob")
    bob_cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        "chat", member_scope("edge-keyring", True),  # read/write member
    )
    await add_collection_recipient(
        owner.client, keyring_name("edge-keyring"),
        {"subKem": bob.device["kemPub"], "userId": bob.user_id, "label": "bob"}, _adder(owner.creds),
        trusted_adders=[owner.creds.device["edPub"]],
    )
    bob_client = sdk(bob_cap, bob.device["edPriv"])

    # Bob can READ the keyring (needed to decrypt) …
    cur = await bob_client.pull(keyring_pull("edge-keyring"))
    # … but replacing it (to list only himself) is denied.
    evil_kr, _cek = create_keyring(bob.device["edPriv"], bob.device["edPub"], [bob.device["kemPub"]])
    with pytest.raises(StarfishHttpError) as exc:
        await bob_client.push(keyring_pull("edge-keyring").replace("/pull/", "/push/"), evil_kr.to_dict(), cur.hash)
    assert exc.value.status == 403

    # The owner is still a recipient — the keyring was not tampered with.
    listing = await list_recipients(owner.client, keyring_name("edge-keyring"), trusted_adders=[owner.creds.device["edPub"]])
    assert owner.creds.device["kemPub"] in {r["subKem"] for r in listing["recipients"]}


async def test_trusted_adders_pin_defeats_hostile_server_keyring_substitution(sdk):
    """The `trusted_adders` pin defends even a HOSTILE SERVER substituting the keyring.

    Owner-binding (`chat:owner`) stops a member/stranger from overwriting the keyring
    through the API, but the *storage layer itself* is still untrusted. We model that
    by writing a malicious keyring straight into the store (bypassing the cap layer),
    wrapping the attacker's CEK for Bob's KEM under the attacker's `addedBy`. Bob
    pulls it and — pinned to the owner — refuses the attacker's entry (it is skipped,
    so no usable entry). The control half (trusting the attacker) proves the pin is
    the gate.
    """
    owner = await _setup_owner(sdk, room="edge-trustpin")
    bob = bootstrap_root_identity("edge-trustpin-bob")
    await add_collection_recipient(
        owner.client, keyring_name("edge-trustpin"),
        {"subKem": bob.device["kemPub"], "userId": bob.user_id, "label": "bob"}, _adder(owner.creds),
        trusted_adders=[owner.creds.device["edPub"]],
    )
    bob_cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        "chat", member_scope("edge-trustpin", True),
    )
    bob_client = sdk(bob_cap, bob.device["edPriv"])
    legit = Keyring.from_dict((await bob_client.pull(keyring_pull("edge-trustpin"))).data)
    create_keyring_encryptor(  # legit: Bob trusts the owner who added him → builds fine
        legit, bob.device["kemPub"], bob.device["kemPriv"], trusted_adders=[owner.creds.device["edPub"]],
    )

    # Hostile server: write an attacker-authored keyring (CEK wrapped for Bob,
    # addedBy = mallory) DIRECTLY into the store, bypassing the cap/owner gate.
    mallory = bootstrap_root_identity("edge-trustpin-mal")
    evil_kr, _cek = create_keyring(
        mallory.device["edPriv"], mallory.device["edPub"], [mallory.device["kemPub"], bob.device["kemPub"]],
    )
    await server.store.put(
        "chatkeyring/rooms/edge-trustpin/_keyring",
        json.dumps({"v": 1, "data": evil_kr.to_dict(), "timestamps": {}, "hash": ""}),
    )

    # Bob pulls the now-malicious keyring. Pinned to the OWNER, he refuses Mallory's
    # CEK (her entry is skipped → no usable entry in the current epoch).
    tampered = Keyring.from_dict((await bob_client.pull(keyring_pull("edge-trustpin"))).data)
    with pytest.raises(ValueError, match="No wrapped key for recipient"):  # skipped, not adopted
        create_keyring_encryptor(
            tampered, bob.device["kemPub"], bob.device["kemPriv"], trusted_adders=[owner.creds.device["edPub"]],
        )
    # Control: it WOULD build if Bob (wrongly) trusted Mallory — the pin is the gate.
    create_keyring_encryptor(
        tampered, bob.device["kemPub"], bob.device["kemPriv"], trusted_adders=[mallory.device["edPub"]],
    )
    # Control: it WOULD build if Bob (wrongly) trusted Mallory — the pin is the gate.
    create_keyring_encryptor(
        tampered, bob.device["kemPub"], bob.device["kemPriv"], trusted_adders=[mallory.device["edPub"]],
    )


async def test_relabeled_added_by_without_signature_is_rejected(sdk):
    """Claiming a trusted `addedBy` without that key's signature does NOT bypass the pin.

    Defense-in-depth for the provenance pin: an attacker who relabels a forged
    entry's `addedBy` to the owner's key — but signs it with their own key — is
    still skipped, because the per-entry `addedSig` is verified against the claimed
    `addedBy`. So `trusted_adders` cannot be defeated by simply lying about the
    author field.
    """
    owner = await _setup_owner(sdk, room="edge-relabel")
    bob = bootstrap_root_identity("edge-relabel-bob")
    mallory = bootstrap_root_identity("edge-relabel-mal")

    # Mallory builds a keyring (entries signed by HER) wrapping her CEK for Bob,
    # then relabels every entry's addedBy to the OWNER's key.
    evil_kr, _cek = create_keyring(
        mallory.device["edPriv"], mallory.device["edPub"], [mallory.device["kemPub"], bob.device["kemPub"]],
    )
    forged = evil_kr.to_dict()
    epoch_key = next(iter(forged["epochs"]))
    for entry in forged["epochs"][epoch_key]["wrappedKeys"]:
        entry["addedBy"] = owner.creds.device["edPub"]  # lie: claim the owner authored it

    # Bob, pinned to the owner, still refuses — the addedSig was Mallory's, not the owner's.
    with pytest.raises(ValueError, match="No wrapped key for recipient"):
        create_keyring_encryptor(
            Keyring.from_dict(forged), bob.device["kemPub"], bob.device["kemPriv"],
            trusted_adders=[owner.creds.device["edPub"]],
        )


async def test_list_recipients_filters_untrusted_entries(sdk):
    """`list_recipients` pinned to the owner FILTERS OUT entries it didn't author.

    Even a hostile server that overwrites the stored keyring with attacker-authored
    entries cannot spoof the membership view: `list_recipients(trusted_adders=[owner])`
    returns only entries whose `addedBy` is trusted and whose `addedSig` verifies, so
    the fabricated recipients are dropped (mirroring the encryptor's provenance pin).
    It is also fail-closed — omitting `trusted_adders` raises.
    """
    owner = await _setup_owner(sdk, room="edge-listprov")
    mallory = bootstrap_root_identity("edge-listprov-mal")
    ghost = bootstrap_root_identity("edge-listprov-ghost")

    # Hostile server: overwrite the stored keyring with a Mallory-authored one that
    # lists a fabricated "ghost" recipient (bypassing the owner-only write gate).
    evil_kr, _cek = create_keyring(
        mallory.device["edPriv"], mallory.device["edPub"], [mallory.device["kemPub"], ghost.device["kemPub"]],
    )
    await server.store.put(
        "chatkeyring/rooms/edge-listprov/_keyring",
        json.dumps({"v": 1, "data": evil_kr.to_dict(), "timestamps": {}, "hash": ""}),
    )

    # Pinned to the owner, the attacker's entries (addedBy = mallory) are filtered out.
    listing = await list_recipients(
        owner.client, keyring_name("edge-listprov"), trusted_adders=[owner.creds.device["edPub"]]
    )
    assert listing["recipients"] == []  # fabricated membership dropped

    # Fail-closed: omitting `trusted_adders` raises rather than returning raw data.
    with pytest.raises(ValueError):
        await list_recipients(owner.client, keyring_name("edge-listprov"))


async def test_echoing_a_hostile_pairing_qr_scope_grants_it(sdk):
    """Echoing a QR's `requested_scope` re-introduces the gap the hardening forbids.

    `assemble_pairing_bundle` now REQUIRES an explicit `granted_scope` (it refuses
    to default to the QR-supplied `requested_scope`, which is attacker-influenceable
    — a `device` cap is a root proxy regardless of its paths). This test pins WHY:
    if the root echoes `granted_scope=parsed.requested_scope`, a hostile QR that
    requests broad access gets exactly that, whereas an independently *bounded*
    scope confines the new device. The root must bound, not echo.
    """
    root = bootstrap_root_identity("edge-hostileqr-root")
    attacker_dev = bootstrap_root_identity("edge-hostileqr-dev").device
    # Hostile QR requests the full owner scope (every room + keyring + member dir).
    parsed = parse_pairing_qr(build_pairing_qr(attacker_dev["edPub"], attacker_dev["kemPub"], owner_scope()))

    echoed = install_pairing_bundle(
        assemble_pairing_bundle(
            {"edPriv": root.device["edPriv"], "edPub": root.device["edPub"]}, parsed, {},
            AssemblePairingBundleOpts(granted_scope=parsed.requested_scope),  # echo = footgun
        ),
        attacker_dev,
    )
    assert "chat/rooms/**" in echoed.credentials.cap_cert["scope"]["paths"]  # got the broad scope

    bounded = install_pairing_bundle(
        assemble_pairing_bundle(
            {"edPriv": root.device["edPriv"], "edPub": root.device["edPub"]}, parsed, {},
            AssemblePairingBundleOpts(granted_scope=member_scope("only-this-room", False)),  # bound it
        ),
        attacker_dev,
    )
    assert bounded.credentials.cap_cert["scope"]["paths"] == ["chat/rooms/only-this-room", "chatkeyring/rooms/only-this-room/_keyring"]


# ── body-size limits: the pre-auth guard caps writes before reading the body ──
async def test_body_size_respects_the_collection_limit(sdk):
    """A ~100 KB write succeeds (chat allows 256 KB); only a >256 KB body is 413.

    The app now threads `max_body_bytes=262_144` into the cap-resolver, so its
    pre-auth guard matches the `chat` collection's ceiling instead of shadowing it
    with the 64 KB default. A ~100 KB message goes through; a body whose ciphertext
    exceeds 256 KB is rejected 413 by the (now-aligned) limit.
    """
    owner = await _setup_owner(sdk, room="edge-big")
    s = owner.sync()
    await s.pull()
    await s.push({**s.data, "messages": [*(s.data.get("messages") or []), _msg("A" * 100_000, owner.creds, "Alice")]})

    s2 = owner.sync()
    await s2.pull()
    with pytest.raises(StarfishHttpError) as exc:
        await s2.push({**s2.data, "messages": [*s2.data["messages"], _msg("B" * 300_000, owner.creds, "Alice")]})
    assert exc.value.status == 413


async def test_profile_oversize_rejected_by_collection_limit(sdk):
    """A profile larger than the collection's 4 KB ceiling is rejected 413.

    The complement of the test above: a 5 KB body is *under* the resolver's 64 KB
    pre-auth guard, so it reaches the per-collection check in the route builder,
    which enforces `profile.max_body_bytes = 4_096`. Pins that the per-collection
    limit is what bites when the body is below the global guard.
    """
    creds = bootstrap_root_identity("edge-prof-big")
    cap = mint_device_cap(
        creds.device["edPriv"], creds.device["edPub"], _sub(creds), account_scope(creds.user_id),
    )
    client = sdk(cap, creds.device["edPriv"])
    with pytest.raises(StarfishHttpError) as exc:
        await client.push(f"/push/user/{creds.user_id}/profile", {"v": 1, "pseudo": "Z" * 5_000}, None)
    assert exc.value.status == 413


# ── per-request binding: a cap is useless without its subject's signing key ───
# The cap-cert names a subject device key (`sub`); every request must ALSO carry
# an Ed25519 signature made with that key, over (method, path, host, body-hash,
# ts, nonce). So a leaked cap-cert alone authorizes nothing, and none of those
# request fields can be swapped after signing.
async def test_stolen_cap_without_subject_key_rejected(sdk):
    """A valid cap presented with a request signed by a DIFFERENT key → 401.

    Models a leaked/exfiltrated cap-cert: the attacker holds the bearer token but
    not the subject device's private key, so the request signature fails.
    """
    owner = await _setup_owner(sdk)
    bob = bootstrap_root_identity("edge-stolen-bob")
    carol = bootstrap_root_identity("edge-stolen-carol")
    bob_cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        "chat", member_scope(ROOM, True),
    )
    # Bob's cap, but requests are signed with Carol's key (the "thief").
    thief = sdk(bob_cap, carol.device["edPriv"])
    with pytest.raises(StarfishHttpError) as exc:
        await thief.pull(room_pull())
    assert exc.value.status == 401


async def test_tampered_subuserid_rejected(sdk):
    """Editing a member cap's `subUserId` (to point at another account) → 401.

    `subUserId` must equal sha256(sub)[:16]; the resolver checks the binding
    independently of the signature, so the mismatch is caught even before signing.
    """
    owner = await _setup_owner(sdk)
    bob = bootstrap_root_identity("edge-subuid")
    cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        "chat", member_scope(ROOM, True),
    )
    tampered = copy.deepcopy(cap)
    tampered["subUserId"] = "0" * 16
    with pytest.raises(StarfishHttpError) as exc:
        await sdk(tampered, bob.device["edPriv"]).pull(room_pull())
    assert exc.value.status == 401


async def test_request_body_tamper_rejected(sdk, http):
    """A request signed over one body but sent with a different body → 401.

    The signature covers sha256(body); swapping the wire body after signing
    (e.g. a proxy rewriting the payload) breaks it. Built as a raw request because
    the SDK always signs exactly what it sends.
    """
    await _setup_owner(sdk)
    bob = bootstrap_root_identity("edge-bodytamper")
    cap = mint_device_cap(bob.device["edPriv"], bob.device["edPub"], _sub(bob), member_scope(ROOM, True))
    cap_b64 = base64.b64encode(stable_stringify(cap).encode("utf-8")).decode("ascii")
    path = room_push()
    sig = sign_request("POST", path, b'{"signed":true}', bob.device["edPriv"], host="testserver")
    headers = {
        "Authorization": f"Cap {cap_b64}",
        "X-Starfish-Sig": sig.sig, "X-Starfish-Ts": str(sig.ts), "X-Starfish-Nonce": sig.nonce,
        "Content-Type": "application/json",
    }
    resp = await http.post(path, content=b'{"sent":"different"}', headers=headers)  # body != signed
    assert resp.status_code == 401


async def test_request_host_binding_rejected(sdk, http):
    """A request whose signature was bound to a different host → 401.

    The `h` field pins a signature to one server; a request captured at host A
    cannot be replayed against host B (here the server reconstructs `testserver`
    but the signature was made for `evil.example`).
    """
    await _setup_owner(sdk)
    bob = bootstrap_root_identity("edge-host")
    cap = mint_device_cap(bob.device["edPriv"], bob.device["edPub"], _sub(bob), member_scope(ROOM, False))
    headers = _signed_get_headers(cap, bob.device["edPriv"], room_pull(), host="evil.example")
    resp = await http.get(room_pull(), headers=headers)
    assert resp.status_code == 401


async def test_request_path_tamper_rejected(sdk, http):
    """A request signed for one path but sent to another → 401.

    Signing covers the path-and-query, so redirecting an authorized request to a
    different resource (here a sibling room) fails — even when the cap's scope
    would cover the new path.
    """
    owner = await _setup_owner(sdk, room="edge-pathA")
    await _setup_owner(sdk, room="edge-pathB")
    bob = bootstrap_root_identity("edge-path")
    # Cap covers BOTH rooms, so only the signature — not scope — can stop the swap.
    cap = mint_device_cap(
        bob.device["edPriv"], bob.device["edPub"], _sub(bob),
        {"ops": ["read", "list"], "collections": ["chat"], "paths": ["chat/rooms/**"]},
    )
    headers = _signed_get_headers(cap, bob.device["edPriv"], room_pull("edge-pathA"))
    resp = await http.get(room_pull("edge-pathB"), headers=headers)  # signed A, sent B
    assert resp.status_code == 401


async def test_oversized_cap_header_rejected(sdk, http):
    """A cap-cert header above the 8 KB cap-header guard → 401 (cap-too-large).

    A padded `scope.paths` blows past `max_cap_header_bytes`; the header is bounded
    before any verification work, so an attacker cannot force expensive parsing
    with a giant token.
    """
    await _setup_owner(sdk)
    bob = bootstrap_root_identity("edge-bighdr")
    cap = mint_device_cap(
        bob.device["edPriv"], bob.device["edPub"], _sub(bob),
        {"ops": ["read"], "collections": ["chat"], "paths": ["chat/rooms/" + "y" * 9_000]},
    )
    headers = _signed_get_headers(cap, bob.device["edPriv"], room_pull())
    resp = await http.get(room_pull(), headers=headers)
    assert resp.status_code == 401


async def test_malformed_cap_header_rejected(sdk, http):
    """An Authorization header that is not valid base64/JSON → 401."""
    await _setup_owner(sdk)
    bob = bootstrap_root_identity("edge-malhdr")
    cap = mint_device_cap(bob.device["edPriv"], bob.device["edPub"], _sub(bob), member_scope(ROOM, False))
    headers = _signed_get_headers(cap, bob.device["edPriv"], room_pull())
    headers["Authorization"] = "Cap not!valid!base64!!"
    resp = await http.get(room_pull(), headers=headers)
    assert resp.status_code == 401


# ── scope semantics: glob matching, denylists, op-by-op asymmetry, footguns ───
async def test_cap_without_paths_grants_collection_wide_access(sdk):
    """A cap that OMITS `scope.paths` is unrestricted within its collection.

    PINS a footgun: empty/absent `paths` means "match every path", so a cap minted
    without paths can read ANY room in the `chat` collection, not just one. The
    app's scope builders always set `paths`; a caller who forgets them hands out a
    collection-wide grant. (The keyring still gates decryption.)
    """
    await _setup_owner(sdk, room="edge-wildA")
    await _setup_owner(sdk, room="edge-wildB")
    eve = bootstrap_root_identity("edge-nopaths")
    cap = mint_device_cap(
        eve.device["edPriv"], eve.device["edPub"], _sub(eve),
        {"ops": ["read", "list"], "collections": ["chat"]},  # no `paths`
    )
    client = sdk(cap, eve.device["edPriv"])
    a = await client.pull(room_pull("edge-wildA"))
    b = await client.pull(room_pull("edge-wildB"))
    assert isinstance(a.data, dict) and isinstance(b.data, dict)  # both reachable


async def test_scope_denylist_blocks_path(sdk):
    """A `!`-prefixed deny rule in `scope.paths` overrides a broad allow.

    `["chat/rooms/**", "!chat/rooms/edge-denyB"]` permits every room except the
    denied one — proving the denylist semantics the resolver documents.
    """
    await _setup_owner(sdk, room="edge-denyA")
    await _setup_owner(sdk, room="edge-denyB")
    bob = bootstrap_root_identity("edge-deny")
    cap = mint_device_cap(
        bob.device["edPriv"], bob.device["edPub"], _sub(bob),
        {"ops": ["read", "list"], "collections": ["chat"],
         "paths": ["chat/rooms/**", "!chat/rooms/edge-denyB"]},
    )
    client = sdk(cap, bob.device["edPriv"])
    await client.pull(room_pull("edge-denyA"))  # allowed
    with pytest.raises(StarfishHttpError) as exc:
        await client.pull(room_pull("edge-denyB"))  # denied by `!` rule
    assert exc.value.status == 403


async def test_write_only_cap_can_write_but_not_read(sdk):
    """A cap with `ops=["write"]` synthesizes only `cap:write:chat` — write yes, read no.

    The resolver maps each op in `scope.ops` to a `cap:<op>:<collection>` role and
    never the reverse, so a write-only cap is 403 on pull. It can still *create* a
    fresh document (first write, no base hash), but note it cannot UPDATE an
    existing one — that needs the current base hash, which requires the read it
    lacks. So a write-only grant is effectively create-only here.
    """
    wo = bootstrap_root_identity("edge-wo")
    cap = mint_device_cap(
        wo.device["edPriv"], wo.device["edPub"], _sub(wo),
        {"ops": ["write"], "collections": ["chat"], "paths": ["chat/rooms/edge-writeonly"]},
    )
    client = sdk(cap, wo.device["edPriv"])

    # Read is refused — no `cap:read:chat` was synthesized.
    with pytest.raises(StarfishHttpError) as exc:
        await client.pull(room_pull("edge-writeonly"))
    assert exc.value.status == 403

    # Creating the (not-yet-existing) document is accepted. Encrypt under the
    # writer's own keyring just to produce a well-formed ciphertext body.
    kr, _cek = create_keyring(wo.device["edPriv"], wo.device["edPub"], [wo.device["kemPub"]])
    enc = create_keyring_encryptor(
        kr, wo.device["kemPub"], wo.device["kemPriv"], trusted_adders=[wo.device["edPub"]],
    )
    await client.push(room_push("edge-writeonly"), enc.encrypt({"messages": []}), None)  # no raise ⇒ 200


async def test_write_only_cap_can_tofu_squat_keyring_but_owner_recovers(sdk):
    """A write-only cap can TOFU-squat a keyring (no read) but the owner recovers.

    `cap:write:chat` alone is enough for the enricher to grant `chat:owner` on the
    first keyring write — even without `cap:read:chat`, so a stranger can plant a
    garbage keyring on a predictable room id. Ownership transfers once the real owner
    lands a valid keyring (same recoverable-DoS model as `test_malformed_keyring_…`).
    """
    room = "edge-wo-tofu"
    stranger = bootstrap_root_identity("edge-wo-tofu-stranger")
    wo_scope = {
        "ops": ["write"],
        "collections": ["chat"],
        "paths": [f"chatkeyring/rooms/{room}/_keyring"],
    }
    s_cap = mint_device_cap(
        stranger.device["edPriv"], stranger.device["edPub"], _sub(stranger), wo_scope,
    )
    s_client = sdk(s_cap, stranger.device["edPriv"])
    await s_client.push(keyring_push(room), {"squat": True}, None)  # 200 — TOFU, no read needed

    owner = bootstrap_root_identity("edge-wo-tofu-owner")
    o_cap = mint_device_cap(owner.device["edPriv"], owner.device["edPub"], _sub(owner), owner_scope())
    o_client = sdk(o_cap, owner.device["edPriv"])
    cur = await o_client.pull(keyring_pull(room))
    keyring, _cek = create_keyring(owner.device["edPriv"], owner.device["edPub"], [owner.device["kemPub"]])
    await o_client.push(keyring_push(room), keyring.to_dict(), cur.hash or None)  # 200 — recovery

    listing = await list_recipients(
        o_client, keyring_name(room), trusted_adders=[owner.device["edPub"]],
    )
    assert owner.device["kemPub"] in {r["subKem"] for r in listing["recipients"]}
    # Write-only stranger cannot read the keyring hash, so it cannot attempt a follow-up rotate.
    with pytest.raises(StarfishHttpError) as exc:
        await s_client.pull(keyring_pull(room))
    assert exc.value.status == 403


async def test_cross_identity_profile_write_denied_even_when_self_signed(sdk):
    """A self-signed root device cap cannot write ANOTHER user's profile → 403.

    A self-signed device cap earns `device:root` (so it clears the profile write
    role), and its scope can be hand-set to name the victim's profile path — yet
    the `{identity}` binding still requires the path identity to equal the cap's
    own identity, so the cross-account write is refused. The two profile guards
    (`device:root` AND identity binding) are independent.
    """
    victim = bootstrap_root_identity("edge-victim")
    attacker = bootstrap_root_identity("edge-attacker")
    # Victim establishes a profile via its own account cap.
    v_cap = mint_device_cap(
        victim.device["edPriv"], victim.device["edPub"], _sub(victim), account_scope(victim.user_id),
    )
    await sdk(v_cap, victim.device["edPriv"]).push(
        f"/push/user/{victim.user_id}/profile", {"v": 1, "pseudo": "Victim"}, None,
    )
    # Attacker self-signs a cap whose scope explicitly names the VICTIM's path.
    a_cap = mint_device_cap(
        attacker.device["edPriv"], attacker.device["edPub"], _sub(attacker), account_scope(victim.user_id),
    )
    with pytest.raises(StarfishHttpError) as exc:
        await sdk(a_cap, attacker.device["edPriv"]).push(
            f"/push/user/{victim.user_id}/profile", {"v": 1, "pseudo": "PWNED"}, None,
        )
    assert exc.value.status == 403

    # Victim's profile is untouched and still publicly readable.
    res = await sdk().pull(f"/pull/user/{victim.user_id}/profile")
    assert res.data["pseudo"] == "Victim"


# ── entitlements: clients cannot write their own slug doc ─────────────────────
async def test_account_cap_cannot_self_grant_entitlements(sdk):
    """A user CANNOT write their own `entitlements` doc to unlock paid slugs.

    The `entitlements` collection's write role is `billing:webhook`, which no client
    cap synthesizes — so even though the account scope nominally covers the path, a
    self-grant push is 403. Paid slugs can only be set by the trusted webhook
    (`/demo/grant`), which writes straight to the store. (Cross-user writes are also
    blocked by the `{identity}` binding.)
    """
    user = bootstrap_root_identity("edge-selfgrant")
    cap = mint_device_cap(
        user.device["edPriv"], user.device["edPub"], _sub(user), account_scope(user.user_id),
    )
    client = sdk(cap, user.device["edPriv"])
    assert await pull_entitlements(client, user.user_id) == []

    with pytest.raises(StarfishHttpError) as own:
        await client.push(f"/push/users/{user.user_id}/entitlements", {"features": ["premium", "enterprise"]}, None)
    assert own.value.status == 403
    assert await pull_entitlements(client, user.user_id) == []  # still nothing — no self-grant

    # Cross-user writes remain blocked by the `{identity}` binding too.
    victim = bootstrap_root_identity("edge-selfgrant-victim")
    with pytest.raises(StarfishHttpError) as other:
        await client.push(f"/push/users/{victim.user_id}/entitlements", {"features": ["premium"]}, None)
    assert other.value.status == 403


# ── revocation + multi-device: revocation is per-cap, not per-identity ────────
async def test_revoking_one_device_leaves_siblings_working(sdk, http):
    """Revoking one device's cap does NOT lock out the account's other devices.

    Two devices are paired to the same root identity, each with its own cap (own
    `sub` + `nonce`). Revoking device 1 by (sub, nonce) makes only that cap 401;
    device 2's distinct cap keeps working. Revocation targets a single credential,
    so losing one device never strands the others.
    """
    await _setup_owner(sdk)  # ensure the room exists to read
    issuer = bootstrap_root_identity("edge-revdev-issuer")  # fresh issuer → fresh generation counter
    caps = []
    for tag in ("edge-revdev-1", "edge-revdev-2"):
        dev = bootstrap_root_identity(tag).device
        parsed = parse_pairing_qr(build_pairing_qr(dev["edPub"], dev["kemPub"], owner_scope()))
        bundle = assemble_pairing_bundle(
            {"edPriv": issuer.device["edPriv"], "edPub": issuer.device["edPub"]}, parsed, {},
            AssemblePairingBundleOpts(granted_scope=parsed.requested_scope),
        )
        cap = install_pairing_bundle(bundle, dev).credentials.cap_cert
        caps.append((cap, dev))

    (cap1, dev1), (cap2, dev2) = caps
    c1, c2 = sdk(cap1, dev1["edPriv"]), sdk(cap2, dev2["edPriv"])
    await c1.pull(room_pull())
    await c2.pull(room_pull())  # both work before revocation

    rev = _sign_revocation_list(
        issuer.device["edPub"], issuer.device["edPriv"],
        [{"sub": cap1["sub"], "nonce": cap1["nonce"]}], generation=1,
    )
    assert (await http.post("/revocations", json=rev)).status_code == 200

    with pytest.raises(StarfishHttpError) as exc:
        await c1.pull(room_pull())  # revoked device
    assert exc.value.status == 401
    await c2.pull(room_pull())  # sibling device unaffected


# ── nonce cache: replay protection is scoped per signing key ──────────────────
async def test_nonce_cache_is_scoped_per_signer(sdk, http):
    """Two different signers may use the SAME nonce — each succeeds.

    The replay cache keys on `<signer_pubkey>|<nonce>`, so one user cannot deny
    service to another by pre-claiming a nonce value, and a replay is only blocked
    for the original signer. (Replay *by the same signer* is covered separately.)
    """
    await _setup_owner(sdk)
    shared_nonce = b"edge-shared-1234"
    statuses = []
    for tag in ("edge-noncescope-1", "edge-noncescope-2"):
        u = bootstrap_root_identity(tag)
        cap = mint_device_cap(u.device["edPriv"], u.device["edPub"], _sub(u), member_scope(ROOM, False))
        headers = _signed_get_headers(cap, u.device["edPriv"], room_pull(), nonce=shared_nonce)
        statuses.append((await http.get(room_pull(), headers=headers)).status_code)
    assert statuses == [200, 200]  # same nonce, different signers, both accepted


# ── observability / exposure: what the demo endpoints reveal ──────────────────
# These pin the trust posture of the app's helper endpoints. They are framed as
# demo conveniences in `server.py`, but the suite makes their exposure explicit so
# a hardening pass (adding auth, auditing denials) shows up as an intended change.
async def test_denied_write_is_audited(sdk, http):
    """A request rejected at the auth layer (403) IS recorded in the audit trail.

    The cap-resolver / role check now emits an audit entry (success=False) on denial,
    so 401/403 rejections are observable through `GET /audit` — not just requests that
    reach the handler.
    """
    owner = await _setup_owner(sdk)
    intruder = bootstrap_root_identity("edge-auditdeny")
    ro_cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": intruder.device["edPub"], "kemPubHex": intruder.device["kemPub"], "userIdHex": intruder.user_id},
        "chat", member_scope(ROOM, False),  # read-only — write will be 403
    )
    client = sdk(ro_cap, intruder.device["edPriv"])
    base = await client.pull(room_pull())  # read allowed → gets the base hash
    with pytest.raises(StarfishHttpError) as exc:
        await client.push(room_push(), owner.encryptor.encrypt({"messages": []}), base.hash)
    assert exc.value.status == 403

    rows = (await http.get("/audit")).json()
    denied = [r for r in rows if r["identity"] == intruder.user_id and r["success"] is False]
    assert denied and all(r["statusCode"] == 403 for r in denied)  # the denial was logged


async def test_audit_endpoint_requires_the_demo_secret(sdk, http):
    """`GET /audit` discloses identities/actions, so it is gated by `X-Demo-Secret`.

    Without the secret the request is 401; with it (the `http` fixture's default) the
    trail is readable. Pins that the admin panel is not world-readable.
    """
    owner = await _setup_owner(sdk)
    s = owner.sync()
    await s.pull()
    await s.push({**s.data, "messages": [*(s.data.get("messages") or []), _msg("seed-audit", owner.creds, "Alice")]})

    denied = await http.get("/audit", headers={"X-Demo-Secret": "wrong"})
    assert denied.status_code == 401

    res = await http.get("/audit")  # http fixture sends the correct secret by default
    assert res.status_code == 200
    rows = res.json()
    assert isinstance(rows, list) and rows
    assert all({"action", "collection", "identity"} <= set(r) for r in rows)


async def test_demo_grant_endpoint_requires_the_demo_secret(sdk, http):
    """`POST /demo/grant` requires `X-Demo-Secret`: no anonymous self-grant of `premium`.

    The endpoint stands in for a trusted billing webhook and is gated by a shared
    secret (and disabled entirely when `STARFISH_DEMO_SECRET` is unset). Without the
    secret it is 401; with it the slug is granted.
    """
    target = bootstrap_root_identity("edge-anongrant")
    target_cap = mint_device_cap(
        target.device["edPriv"], target.device["edPub"], _sub(target), account_scope(target.user_id),
    )
    target_client = sdk(target_cap, target.device["edPriv"])
    assert await pull_entitlements(target_client, target.user_id) == []

    denied = await http.post("/demo/grant", json={"userId": target.user_id}, headers={"X-Demo-Secret": "wrong"})
    assert denied.status_code == 401
    assert await pull_entitlements(target_client, target.user_id) == []  # not granted without the secret

    granted = await http.post("/demo/grant", json={"userId": target.user_id})  # default secret
    assert granted.status_code == 200
    assert "premium" in await pull_entitlements(target_client, target.user_id)


async def test_demo_endpoints_disabled_when_secret_unset(http):
    """When `STARFISH_DEMO_SECRET` is unset, demo/admin routes return 403 (disabled).

    `conftest` sets the secret for the bulk of the suite; this pins the secure-by-default
    path documented in `server.py` by clearing the module-level gate at runtime.
    """
    original = server._DEMO_SECRET
    try:
        server._DEMO_SECRET = None
        for method, path, kwargs in (
            ("get", "/audit", {}),
            ("post", "/demo/grant", {"json": {"userId": "deadbeef" * 4}}),
            ("post", "/demo/revoke", {"json": {"userId": "deadbeef" * 4}}),
        ):
            resp = await getattr(http, method)(path, **kwargs)
            assert resp.status_code == 403, f"{method} {path}"
            assert "disabled" in resp.json().get("error", "").lower()
    finally:
        server._DEMO_SECRET = original


# ── keyring epoch monotonicity: rotations are reversible (no epoch floor) ──────
async def test_removed_member_cannot_roll_the_keyring_back(sdk):
    """A removed member CANNOT roll the keyring back to re-admit itself → 403.

    Owner-binding closes the rollback vector: even though `remove_recipient` doesn't
    revoke the member's cap, the keyring write role is now `chat:owner`, so the
    removed member's attempt to push back a pre-removal snapshot is refused. Forward
    secrecy from a removal therefore holds without also revoking the cap. (A hostile
    *server* rolling the doc back is caught client-side by the L2 `min_epoch` guard.)
    """
    owner = await _setup_owner(sdk, room="edge-rollback")
    bob = bootstrap_root_identity("edge-rollback-bob")
    await add_collection_recipient(
        owner.client, keyring_name("edge-rollback"),
        {"subKem": bob.device["kemPub"], "userId": bob.user_id, "label": "bob"}, _adder(owner.creds),
        trusted_adders=[owner.creds.device["edPub"]],
    )
    bob_cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        "chat", member_scope("edge-rollback", True),
    )
    bob_client = sdk(bob_cap, bob.device["edPriv"])
    saved = (await bob_client.pull(keyring_pull("edge-rollback"))).data  # snapshot including bob

    # Owner removes Bob → epoch rotates; Bob is no longer a recipient.
    await remove_recipient(
        owner.client, keyring_name("edge-rollback"), [bob.device["kemPub"]], _adder(owner.creds),
        trusted_adders=[owner.creds.device["edPub"]],
    )
    removed = await list_recipients(owner.client, keyring_name("edge-rollback"), trusted_adders=[owner.creds.device["edPub"]])
    assert bob.device["kemPub"] not in {r["subKem"] for r in removed["recipients"]}

    # Bob tries to push the saved snapshot back — denied (owner-only write).
    cur = await bob_client.pull(keyring_pull("edge-rollback"))
    with pytest.raises(StarfishHttpError) as exc:
        await bob_client.push(keyring_pull("edge-rollback").replace("/pull/", "/push/"), saved, cur.hash)
    assert exc.value.status == 403
    still = await list_recipients(owner.client, keyring_name("edge-rollback"), trusted_adders=[owner.creds.device["edPub"]])
    assert bob.device["kemPub"] not in {r["subKem"] for r in still["recipients"]}  # not re-admitted


# ── audit trail durability: the in-memory log is bounded but no longer tiny ───
async def test_audit_log_resists_small_floods(sdk, http):
    """An earlier action survives a modest burst of later writes (raised bound).

    The audit log's bound was raised from 100 to `AUDIT_LOG_MAXLEN` (10_000), so a
    handful of later pushes no longer buries an earlier row. It is still in-memory and
    bounded (production must stream to a persistent sink) — but a small flood like the
    one below no longer evicts the marker.
    """
    owner = await _setup_owner(sdk, room="edge-audit")
    marker = bootstrap_root_identity("edge-audit-marker")
    await add_collection_recipient(
        owner.client, keyring_name("edge-audit"),
        {"subKem": marker.device["kemPub"], "userId": marker.user_id, "label": "marker"}, _adder(owner.creds),
        trusted_adders=[owner.creds.device["edPub"]],
    )
    marker_cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": marker.device["edPub"], "kemPubHex": marker.device["kemPub"], "userIdHex": marker.user_id},
        "chat", member_scope("edge-audit", True),
    )
    await add_member_entry(owner.client, members_name("edge-audit"), marker_cap, label="marker")  # roster → can post
    marker_client = sdk(marker_cap, marker.device["edPriv"])
    kr = Keyring.from_dict((await marker_client.pull(keyring_pull("edge-audit"))).data)
    marker_enc = create_keyring_encryptor(
        kr, marker.device["kemPub"], marker.device["kemPriv"],
        trusted_adders=[owner.creds.device["edPub"]],
    )
    ms = SyncManager(
        marker_client, room_pull("edge-audit"), room_push("edge-audit"),
        encryptor=marker_enc, on_conflict=_union_messages,
    )
    await ms.pull()
    await ms.push({**ms.data, "messages": [*ms.data["messages"], _msg("marker-push", owner.creds, "Marker")]})
    assert any(r["identity"] == marker.user_id for r in (await http.get("/audit")).json())  # logged now

    # A modest flood (well under the raised bound) no longer evicts the marker.
    for i in range(110):
        s = owner.sync(); await s.pull()
        await s.push({**s.data, "messages": [*(s.data.get("messages") or []), _msg(f"flood-{i}", owner.creds, "A")]})

    rows = (await http.get("/audit")).json()
    assert any(r["identity"] == marker.user_id for r in rows)          # marker survived the flood
    assert len(rows) <= server.AUDIT_LOG_MAXLEN and server.AUDIT_LOG_MAXLEN >= 10_000  # bounded, but large


# ── containment / negative scope: traversal, time window, anon, mismatch ──────
async def test_roomid_path_traversal_is_contained(sdk):
    """A `..`-laden room id does not escape the chat namespace — it 404s, not 500/200.

    Even with a broad `chat/rooms/**` scope, a traversal room id resolves to no
    document (the filesystem store rejects `..` segments and the route finds
    nothing) rather than reading a sibling collection or crashing.
    """
    owner = await _setup_owner(sdk)
    for room_id in ("..%2F..%2Fsecret", "x/../../y"):
        with pytest.raises(StarfishHttpError) as exc:
            await owner.client.pull(f"/pull/chat/rooms/{room_id}")
        assert exc.value.status in (400, 404)  # contained: no escape, no 500, no foreign data


async def test_unicode_or_homograph_room_id_is_rejected(sdk):
    """A room id with a homograph / RTL-override / non-ASCII char is rejected 400.

    Companion to the `..` containment test: the server pins room ids to an ASCII
    charset (`validate_path_segment`, which runs before auth), so a Cyrillic-'а'
    look-alike of an existing room — or a Trojan-source RTL override — can never
    address or squat a storage key. This closes homograph confusion that a bytes-only
    `..`/`//` guard would miss.
    """
    owner = await _setup_owner(sdk)
    for room_id in ("аdmin", "‮general", "café"):  # Cyrillic 'а', RTL override, é
        with pytest.raises(StarfishHttpError) as exc:
            await owner.client.pull(f"/pull/chat/rooms/{room_id}")
        assert exc.value.status == 400


async def test_not_yet_valid_cap_rejected(sdk):
    """A device cap whose `nbf` is in the future (beyond the skew) is 401.

    The mirror of the e2e expired-cap test: a cap minted to become valid later
    cannot be used early. Provisioned with `nbf = now + 1h` so it is firmly outside
    the 5-minute clock skew.
    """
    owner = await _setup_owner(sdk)
    provisioned = provision_device(
        {"edPriv": owner.creds.device["edPriv"], "edPub": owner.creds.device["edPub"]},
        ProvisionDeviceOpts(scope=member_scope(ROOM, False), nbf=int(time.time()) + 3600, ttl_sec=7200),
    )
    client = sdk(provisioned.bundle.cap_cert, provisioned.device_keys["edPriv"])
    with pytest.raises(StarfishHttpError) as exc:
        await client.pull(room_pull())
    assert exc.value.status == 401


async def test_inverted_validity_window_cap_is_rejected(sdk):
    """A device cap whose `exp` is BEFORE its `nbf` is rejected 401.

    The verifier rejects `exp <= nbf` before the time gates, so a backwards
    window can't slip through during the instant where the skew margins overlap.
    Provisioned with `nbf = now + 100` and `ttl = -200` → `exp = now - 100`
    (inverted); with the default 300s skew, `now` would otherwise sit inside
    `[nbf-skew, exp+skew]`, so this proves the dedicated check, not the time gate,
    is what rejects it. Mirror of `test_not_yet_valid_cap_rejected`.
    """
    owner = await _setup_owner(sdk)
    now = int(time.time())
    provisioned = provision_device(
        {"edPriv": owner.creds.device["edPriv"], "edPub": owner.creds.device["edPub"]},
        ProvisionDeviceOpts(scope=member_scope(ROOM, False), nbf=now + 100, ttl_sec=-200),
    )
    client = sdk(provisioned.bundle.cap_cert, provisioned.device_keys["edPriv"])
    with pytest.raises(StarfishHttpError) as exc:
        await client.pull(room_pull())
    assert exc.value.status == 401


async def test_anonymous_cannot_write_profile(sdk):
    """An unauthenticated request cannot write a profile, though reads stay public.

    Profile reads are `public`, but writes need `device:root`; an anonymous request
    carries no roles, so the write is denied even as the public read keeps working.
    """
    owner = bootstrap_root_identity("edge-anonprof")
    o_cap = mint_device_cap(
        owner.device["edPriv"], owner.device["edPub"], _sub(owner), account_scope(owner.user_id),
    )
    await sdk(o_cap, owner.device["edPriv"]).push(
        f"/push/user/{owner.user_id}/profile", {"v": 1, "pseudo": "Owner"}, None,
    )
    anon = sdk()  # no cap
    with pytest.raises(StarfishHttpError) as exc:
        await anon.push(f"/push/user/{owner.user_id}/profile", {"v": 1, "pseudo": "anon-overwrite"}, None)
    assert exc.value.status in (401, 403)
    assert (await anon.pull(f"/pull/user/{owner.user_id}/profile")).data["pseudo"] == "Owner"  # read still public


async def test_cap_collection_and_path_must_agree(sdk):
    """A cap whose `collections` names a different collection than the target path → 403.

    A member cap minted for the `profile` collection but pointed (via `scope.paths`)
    at a chat room synthesizes `cap:read:profile`, not the `cap:read:chat` the chat
    collection requires — so the role gate fails even though the path matches.
    """
    owner = await _setup_owner(sdk)
    eve = bootstrap_root_identity("edge-colmismatch")
    cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": eve.device["edPub"], "kemPubHex": eve.device["kemPub"], "userIdHex": eve.user_id},
        "profile",  # cap is for the `profile` collection …
        {"ops": ["read", "list"], "collections": ["profile"], "paths": [f"chat/rooms/{ROOM}"]},  # … but path is a chat room
    )
    with pytest.raises(StarfishHttpError) as exc:
        await sdk(cap, eve.device["edPriv"]).pull(room_pull())
    assert exc.value.status == 403


async def test_blind_overwrite_of_existing_doc_conflicts(sdk):
    """A push with `baseHash=None` to an EXISTING document is a 409, not a clobber.

    Optimistic-concurrency control means you cannot blind-overwrite live data: a
    create-style push (no base hash) against a path that already holds a document
    conflicts. (To replace it you must read its current hash first — which is why
    the room-overwrite gap requires read access to the room.)
    """
    owner = await _setup_owner(sdk, room="edge-blind")
    with pytest.raises(ConflictError):
        await owner.client.push(room_push("edge-blind"), owner.encryptor.encrypt({"messages": []}), None)


# ── author fields: identity is pinned, but the signature is not verified ──────
async def test_author_pubkey_cannot_be_spoofed_at_rest(sdk, http):
    """A push that claims a different `authorPubkey` is recorded under the WRITER's id.

    The server ignores the body's `authorPubkey` and stamps the document's author
    with the *authenticated* cap identity, so a writer cannot attribute a write to
    someone else at rest — even via a hand-crafted request that sets `authorPubkey`.
    """
    user = bootstrap_root_identity("edge-authorpub")
    cap = mint_device_cap(user.device["edPriv"], user.device["edPub"], _sub(user), account_scope(user.user_id))
    cap_b64 = base64.b64encode(stable_stringify(cap).encode("utf-8")).decode("ascii")
    path = f"/push/user/{user.user_id}/profile"
    body = json.dumps({
        "data": {"v": 1, "pseudo": "Real"}, "baseHash": None,
        "authorPubkey": "deadbeefdeadbeef",          # spoof attempt
        "authorSignature": "irrelevant",
    }).encode("utf-8")
    sig = sign_request("POST", path, body, user.device["edPriv"], host="testserver")
    resp = await http.post(path, content=body, headers={
        "Authorization": f"Cap {cap_b64}",
        "X-Starfish-Sig": sig.sig, "X-Starfish-Ts": str(sig.ts), "X-Starfish-Nonce": sig.nonce,
        "Content-Type": "application/json",
    })
    assert resp.status_code == 200

    stored = await sdk().pull(f"/pull/user/{user.user_id}/profile")
    assert stored.author_pubkey == user.user_id          # the writer's real identity
    assert stored.author_pubkey != "deadbeefdeadbeef"     # not the spoofed value


async def test_author_signature_is_not_verified_server_side(sdk, http):
    """The server stores a client-supplied `authorSignature` verbatim, unchecked.

    PINS a property apps must know: author non-repudiation is an END-TO-END
    guarantee — the server is a dumb store for `authorSignature` and never verifies
    it, so a writer can attach a bogus signature and it round-trips on read. A
    consumer that trusts pulled documents must verify the signature itself.
    """
    user = bootstrap_root_identity("edge-authorsig")
    cap = mint_device_cap(user.device["edPriv"], user.device["edPub"], _sub(user), account_scope(user.user_id))
    cap_b64 = base64.b64encode(stable_stringify(cap).encode("utf-8")).decode("ascii")
    path = f"/push/user/{user.user_id}/profile"
    bogus = "not-a-real-ed25519-signature"
    body = json.dumps({"data": {"v": 1, "pseudo": "Real"}, "baseHash": None, "authorSignature": bogus}).encode("utf-8")
    sig = sign_request("POST", path, body, user.device["edPriv"], host="testserver")
    resp = await http.post(path, content=body, headers={
        "Authorization": f"Cap {cap_b64}",
        "X-Starfish-Sig": sig.sig, "X-Starfish-Ts": str(sig.ts), "X-Starfish-Nonce": sig.nonce,
        "Content-Type": "application/json",
    })
    assert resp.status_code == 200  # accepted despite the garbage signature

    stored = await sdk().pull(f"/pull/user/{user.user_id}/profile")
    assert stored.author_signature == bogus  # stored and returned unverified


# ── feature/layout: `?withKeyring=1` degrades gracefully on this app ──────────
async def test_with_keyring_optimization_degrades_gracefully(sdk):
    """`?withKeyring=1` on the `chat` room returns 200 with `keyring: null`, not 500.

    The `withKeyring` optimization reads the sibling `chat/rooms/<id>/_keyring`, but
    this app stores the keyring in a SEPARATE namespace (`chatkeyring/...`), so the
    sibling read hits the room *file* as a directory. The server now catches the
    store error and returns `keyring: null` instead of crashing — so a read-cap
    holder can no longer 500 the server with one query param.
    """
    await _setup_owner(sdk, room="edge-withkeyring")
    reader = bootstrap_root_identity("edge-withkeyring-reader")
    cap = mint_device_cap(
        reader.device["edPriv"], reader.device["edPub"], _sub(reader), member_scope("edge-withkeyring", False),
    )
    signed_path = f"/pull/chat/rooms/edge-withkeyring?withKeyring=1"
    headers = _signed_get_headers(cap, reader.device["edPriv"], signed_path)

    transport = httpx.ASGITransport(app=server.app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url=BASE_URL) as raw:
        resp = await raw.get(signed_path, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["keyring"] is None


# ── rendezvous pairing: the LIB permits an unpinned install (app must pin) ────
async def test_rendezvous_without_root_pin_enables_mitm(sdk):
    """Documents the LIBRARY's residual permissiveness: `install_pairing_bundle`'s
    `expected_root_ed_pub` is OPTIONAL, so installing WITHOUT it adopts whatever
    bundle sits in the public, anonymously-overwritable `_pairing/{rendezvousId}`
    slot — including one an attacker planted under their own root (account takeover).

    The library keeps the pin optional by design (some callers learn the root only
    from the bundle). The EXAMPLE APP closes this: `fetchAndBuildDeviceSession`
    (frontend `starfish.ts`) makes `expectedRootEdPub` REQUIRED and throws without
    it, so the app never performs an unpinned install. This test pins the lib
    behavior; the second half shows the pin rejecting the planted bundle.
    """
    legit = bootstrap_root_identity("edge-rdv-legit")
    attacker = bootstrap_root_identity("edge-rdv-attacker")
    new_device = generate_device_keys()
    parsed = parse_pairing_qr(build_pairing_qr(new_device["edPub"], new_device["kemPub"], owner_scope()))

    # The legitimate root pushes its bundle first …
    legit_bundle = assemble_pairing_bundle(
        {"edPriv": legit.device["edPriv"], "edPub": legit.device["edPub"]}, parsed, {},
        AssemblePairingBundleOpts(granted_scope=owner_scope()),
    )
    await push_pairing_bundle(sdk(), parsed.qr_nonce, legit_bundle)
    # … but an anonymous attacker OVERWRITES the public slot with a bundle from their own root.
    attacker_bundle = assemble_pairing_bundle(
        {"edPriv": attacker.device["edPriv"], "edPub": attacker.device["edPub"]}, parsed, {},
        AssemblePairingBundleOpts(granted_scope=owner_scope()),
    )
    await push_pairing_bundle(sdk(), parsed.qr_nonce, attacker_bundle)  # no cap required (public write)

    fetched = await fetch_pairing_bundle(sdk(), parsed.qr_nonce)
    # A device that does NOT pin the root adopts the attacker's identity → MITM.
    hijacked = install_pairing_bundle(fetched, new_device)  # expected_root_ed_pub omitted
    assert hijacked.credentials.user_id == attacker.user_id
    assert hijacked.credentials.user_id != legit.user_id

    # Defense: pinning the legitimate root (learned out-of-band) rejects the planted bundle.
    with pytest.raises(Exception):
        install_pairing_bundle(fetched, new_device, expected_root_ed_pub=legit.device["edPub"])


# ── more identity binding + content hygiene ───────────────────────────────────
async def test_cross_user_devices_directory_write_denied(sdk):
    """A cap naming ANOTHER user's `_devices` path cannot write it → 403.

    The linked-device directory is `{identity}`-bound, so even a self-signed device
    cap whose scope explicitly covers the victim's `_devices` path is refused — a user
    can only manage their own device list.
    """
    attacker = bootstrap_root_identity("edge-devdir-atk")
    victim = bootstrap_root_identity("edge-devdir-vic")
    cap = mint_device_cap(
        attacker.device["edPriv"], attacker.device["edPub"], _sub(attacker),
        {"ops": ["read", "list", "write"], "collections": ["devices"], "paths": [f"users/{victim.user_id}/_devices"]},
    )
    with pytest.raises(StarfishHttpError) as exc:
        await sdk(cap, attacker.device["edPriv"]).push(
            f"/push/users/{victim.user_id}/_devices", {"v": 1, "entries": []}, None,
        )
    assert exc.value.status == 403


async def test_dangerous_object_keys_are_stripped_from_documents(sdk):
    """`__proto__` / `constructor` keys are stripped from a stored document.

    The server's `deep_sanitize` drops prototype-pollution-style keys before storage,
    so a crafted write cannot smuggle them back to clients on read — a defense that
    matters most for the TypeScript SDK / browser consumers. Legitimate keys survive.
    """
    user = bootstrap_root_identity("edge-sanitize")
    cap = mint_device_cap(user.device["edPriv"], user.device["edPub"], _sub(user), account_scope(user.user_id))
    await sdk(cap, user.device["edPriv"]).push(
        f"/push/user/{user.user_id}/profile",
        {"v": 1, "pseudo": "X", "__proto__": {"polluted": True}, "constructor": {"x": 1}, "normal": 2},
        None,
    )
    stored = (await sdk().pull(f"/pull/user/{user.user_id}/profile")).data
    assert "__proto__" not in stored and "constructor" not in stored  # stripped
    assert stored["pseudo"] == "X" and stored["normal"] == 2          # legit keys survive


# ── member directory: overwrite-DoS gap, but enumeration is validated ─────────
async def test_stranger_cannot_wipe_member_directory(sdk):
    """A self-signed stranger CANNOT overwrite/wipe the member directory → 403.

    The `_members` write role is now `chat:owner`, so a self-signed device cap scoped
    to the members path can no longer replace the roster (owner-binding). The real
    membership survives the attempt. (Reads of `_members` need `cap:read:chat`, which
    a stranger's chat cap still synthesizes — but writes are owner-only.)
    """
    owner = await _setup_owner(sdk, room="edge-memdir")
    bob = bootstrap_root_identity("edge-memdir-bob")
    bob_cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        "chat", member_scope("edge-memdir", True),
    )
    await add_member_entry(owner.client, members_name("edge-memdir"), bob_cap, label="bob")
    assert any(m.get("subUserId") == bob.user_id for m in await list_members(owner.client, members_name("edge-memdir")))

    stranger = bootstrap_root_identity("edge-memdir-stranger")
    s_cap = mint_device_cap(
        stranger.device["edPriv"], stranger.device["edPub"], _sub(stranger),
        {"ops": ["read", "list", "write"], "collections": ["chat"], "paths": ["chatmembers/rooms/edge-memdir/_members"]},
    )
    s_client = sdk(s_cap, stranger.device["edPriv"])
    cur = await s_client.pull(members_pull("edge-memdir"))  # read still allowed
    with pytest.raises(StarfishHttpError) as exc:
        await s_client.push(
            members_push("edge-memdir"),
            {"v": 1, "entries": [{"subUserId": "deadbeefdeadbeef", "label": "ghost-admin"}]}, cur.hash,
        )
    assert exc.value.status == 403

    # The real roster is intact — the wipe was refused.
    members = await list_members(owner.client, members_name("edge-memdir"))
    assert any(m.get("subUserId") == bob.user_id for m in members)


async def test_member_cannot_read_or_write_member_directory(sdk):
    """A read/write member's scope excludes `_members` → 403 on both read and write.

    The roster is owner-managed: a member cap covers only the room doc + keyring, so a
    member can neither enumerate the membership nor tamper with it.
    """
    owner = await _setup_owner(sdk, room="edge-memscope")
    member = bootstrap_root_identity("edge-memscope-m")
    cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": member.device["edPub"], "kemPubHex": member.device["kemPub"], "userIdHex": member.user_id},
        "chat", member_scope("edge-memscope", True),
    )
    client = sdk(cap, member.device["edPriv"])
    with pytest.raises(StarfishHttpError) as r:
        await client.pull(members_pull("edge-memscope"))
    assert r.value.status == 403
    with pytest.raises(StarfishHttpError) as w:
        await client.push(members_push("edge-memscope"), {"v": 1, "entries": []}, None)
    assert w.value.status == 403


async def test_cross_user_devices_directory_read_denied(sdk):
    """A cap naming another user's `_devices` path cannot READ it → 403 (read complements write).

    The device directory's `{identity}` binding gates reads too, so one user cannot
    enumerate another's linked devices.
    """
    attacker = bootstrap_root_identity("edge-devread-atk")
    victim = bootstrap_root_identity("edge-devread-vic")
    cap = mint_device_cap(
        attacker.device["edPriv"], attacker.device["edPub"], _sub(attacker),
        {"ops": ["read", "list"], "collections": ["devices"], "paths": [f"users/{victim.user_id}/_devices"]},
    )
    with pytest.raises(StarfishHttpError) as exc:
        await sdk(cap, attacker.device["edPriv"]).pull(f"/pull/users/{victim.user_id}/_devices")
    assert exc.value.status == 403


async def test_failed_signature_does_not_consume_the_nonce(sdk, http):
    """A bad-signature request (401) does NOT burn its nonce — a later valid one reuses it.

    The nonce is recorded only after the request signature verifies, so an attacker
    cannot grief a victim by pre-claiming nonces with forged-signature requests.
    """
    await _setup_owner(sdk, room="edge-nonceburn")
    carol = bootstrap_root_identity("edge-nonceburn")
    cap = mint_device_cap(
        carol.device["edPriv"], carol.device["edPub"], _sub(carol), member_scope("edge-nonceburn", False),
    )
    cap_b64 = base64.b64encode(stable_stringify(cap).encode("utf-8")).decode("ascii")
    path = room_pull("edge-nonceburn")
    good = sign_request("GET", path, b"", carol.device["edPriv"], host="testserver", nonce=b"edge-nonce-burn1")
    base_headers = {
        "Authorization": f"Cap {cap_b64}", "X-Starfish-Ts": str(good.ts),
        "X-Starfish-Nonce": good.nonce, "Accept": "application/json",
    }
    # A forged signature with this nonce is rejected …
    bad = await http.get(path, headers={**base_headers, "X-Starfish-Sig": base64.b64encode(b"\x00" * 64).decode("ascii")})
    assert bad.status_code == 401
    # … and the genuine signature with the SAME nonce still succeeds.
    ok = await http.get(path, headers={**base_headers, "X-Starfish-Sig": good.sig})
    assert ok.status_code == 200


# ── shared role names: a broad `chat` cap READS widely but can't write owner docs ──
async def test_pathless_chat_cap_reads_widely_but_cannot_write_keyring(sdk):
    """A `chat`-scoped cap with NO paths reads every room's keyring/members, but the
    owner-only write gate stops it from overwriting them.

    `chatkeyring` and `chatmembers` reuse the `cap:read:chat` role, so a chat cap that
    omits `paths` can READ the keyring + roster of any room (the residual reach of the
    shared-role-name design). But their WRITE role is now `chat:owner`, so the same
    over-broad cap cannot clobber the keyring or wipe the roster of a room it does not
    own — the overwrite is 403.
    """
    owner = await _setup_owner(sdk, room="edge-reach")
    stranger = bootstrap_root_identity("edge-reach-stranger")
    cap = mint_device_cap(  # collection `chat`, NO paths → matches the read role family
        stranger.device["edPriv"], stranger.device["edPub"], _sub(stranger),
        {"ops": ["read", "list", "write"], "collections": ["chat"]},
    )
    client = sdk(cap, stranger.device["edPriv"])

    # Reads still reach the room doc, keyring, AND member directory of a room it never named.
    assert isinstance((await client.pull(room_pull("edge-reach"))).data, dict)
    cur_kr = await client.pull(keyring_pull("edge-reach"))
    assert isinstance((await client.pull(members_pull("edge-reach"))).data, dict)

    # But OVERWRITING the keyring is denied (owner-only) — the owner stays a recipient.
    evil_kr, _cek = create_keyring(stranger.device["edPriv"], stranger.device["edPub"], [stranger.device["kemPub"]])
    with pytest.raises(StarfishHttpError) as exc:
        await client.push(keyring_pull("edge-reach").replace("/pull/", "/push/"), evil_kr.to_dict(), cur_kr.hash)
    assert exc.value.status == 403
    listing = await list_recipients(owner.client, keyring_name("edge-reach"), trusted_adders=[owner.creds.device["edPub"]])
    assert owner.creds.device["kemPub"] in {r["subKem"] for r in listing["recipients"]}  # owner intact


async def test_wildcard_collection_scope_does_not_match_concrete_roles(sdk):
    """A `collections:["*"]` cap does NOT inherit concrete-collection access → 403.

    Role matching is exact: a wildcard collection synthesizes `cap:<op>:*`, which does
    not satisfy a collection whose role is `cap:<op>:chat`. So you cannot escalate into
    the chat role family with a `*` collection (defense). The self-signed cap can still
    write its OWN profile — that gate is `device:root` (iss == sub) + the `{identity}`
    binding, independent of the collection wildcard.
    """
    await _setup_owner(sdk, room="edge-wildcol")
    user = bootstrap_root_identity("edge-wildcol-user")
    cap = mint_device_cap(
        user.device["edPriv"], user.device["edPub"], _sub(user),
        {"ops": ["read", "list", "write"], "collections": ["*"], "paths": ["**"]},
    )
    client = sdk(cap, user.device["edPriv"])
    with pytest.raises(StarfishHttpError) as exc:
        await client.pull(room_pull("edge-wildcol"))  # cap:read:* ≠ cap:read:chat
    assert exc.value.status == 403

    # device:root is a separate gate, so the user can still write its OWN profile.
    await client.push(f"/push/user/{user.user_id}/profile", {"v": 1, "pseudo": "Self"}, None)
    assert (await sdk().pull(f"/pull/user/{user.user_id}/profile")).data["pseudo"] == "Self"


# ── more exposure + robustness ────────────────────────────────────────────────
async def test_demo_revoke_endpoint_requires_the_demo_secret(sdk, http):
    """`POST /demo/revoke` requires `X-Demo-Secret`: no anonymous stripping of entitlements.

    Companion to the gated `/demo/grant`: without the secret a caller cannot wipe a
    paying user's `premium` slug (401), so paid features can't be griefed anonymously.
    """
    payer = bootstrap_root_identity("edge-revoke-payer")
    cap = mint_device_cap(payer.device["edPriv"], payer.device["edPub"], _sub(payer), account_scope(payer.user_id))
    client = sdk(cap, payer.device["edPriv"])
    await http.post("/demo/grant", json={"userId": payer.user_id})  # trusted webhook grants premium
    assert "premium" in await pull_entitlements(client, payer.user_id)

    denied = await http.post("/demo/revoke", json={"userId": payer.user_id}, headers={"X-Demo-Secret": "wrong"})
    assert denied.status_code == 401
    assert "premium" in await pull_entitlements(client, payer.user_id)  # still premium — not stripped

    stripped = await http.post("/demo/revoke", json={"userId": payer.user_id})  # default secret
    assert stripped.status_code == 200
    assert await pull_entitlements(client, payer.user_id) == []


async def test_malformed_document_pushes_are_rejected(sdk, http):
    """A push whose `data` isn't an object, or whose `baseHash` isn't a string, → 400.

    The push handler validates the envelope shape before storage, so a client cannot
    persist a non-document body (defense / robustness). Built raw because the SDK
    always wraps a dict.
    """
    user = bootstrap_root_identity("edge-malformed")
    cap = mint_device_cap(user.device["edPriv"], user.device["edPub"], _sub(user), account_scope(user.user_id))
    cap_b64 = base64.b64encode(stable_stringify(cap).encode("utf-8")).decode("ascii")
    path = f"/push/user/{user.user_id}/profile"
    for body in ({"data": [1, 2, 3], "baseHash": None}, {"data": None, "baseHash": None}, {"data": {"v": 1}, "baseHash": 123}):
        raw = json.dumps(body).encode("utf-8")
        sig = sign_request("POST", path, raw, user.device["edPriv"], host="testserver")
        resp = await http.post(path, content=raw, headers={
            "Authorization": f"Cap {cap_b64}",
            "X-Starfish-Sig": sig.sig, "X-Starfish-Ts": str(sig.ts), "X-Starfish-Nonce": sig.nonce,
            "Content-Type": "application/json",
        })
        assert resp.status_code == 400


async def test_empty_ops_cap_grants_nothing(sdk):
    """A cap with `ops: []` synthesizes no `cap:<op>:<collection>` roles → 403.

    The role set is built only from the ops present in scope, so an empty ops list is
    a credential that authenticates but authorizes nothing.
    """
    owner = await _setup_owner(sdk, room="edge-emptyops")
    user = bootstrap_root_identity("edge-emptyops-u")
    cap = mint_device_cap(
        user.device["edPriv"], user.device["edPub"], _sub(user),
        {"ops": [], "collections": ["chat"], "paths": ["chat/rooms/edge-emptyops"]},
    )
    with pytest.raises(StarfishHttpError) as exc:
        await sdk(cap, user.device["edPriv"]).pull(room_pull("edge-emptyops"))
    assert exc.value.status == 403


async def test_document_timestamps_are_server_authoritative(sdk):
    """A client cannot dictate a document's stored timestamp (no LWW manipulation).

    The server stamps writes with its own clock (`time.time_ns()`), so an injected
    far-future `timestamps`/value in the pushed body does not become the doc's
    timestamp — a writer can't make its version permanently "win" future merges.
    """
    user = bootstrap_root_identity("edge-ts")
    cap = mint_device_cap(user.device["edPriv"], user.device["edPub"], _sub(user), account_scope(user.user_id))
    res = await sdk(cap, user.device["edPriv"]).push(
        f"/push/user/{user.user_id}/profile",
        {"v": 1, "pseudo": "TS", "timestamps": {"pseudo": 9_999_999_999_999}},  # absurd injected value
        None,
    )
    # Server clock, not the injected ~year-2286 value.
    assert 1_700_000_000_000 < res.timestamp < 9_000_000_000_000


# ══════════════════════════════════════════════════════════════════════════════
# ROUND R1 — owner-binding internals & availability of the public slots
#
# The owner-role enricher (`server.make_owner_role_enricher`) anchors `chat:owner`
# to the keyring's epoch-1 genesis adder. These probe its corners: what an
# UNPARSEABLE keyring does to ownership (a brick-vs-recover question), whether a
# squat written before any keyring is recoverable, whether ownership survives
# epoch rotation and even the owner's own eviction from the recipient set, and the
# availability of the deliberately-public rendezvous slot.
# ══════════════════════════════════════════════════════════════════════════════
async def test_malformed_keyring_does_not_permanently_brick_the_room(sdk):
    """A garbage keyring written during the TOFU window must not lock out the owner.

    The enricher derives the owner from the keyring's epoch-1 genesis adder. If a
    stranger wins the create race and writes an UNPARSEABLE keyring (no `epochs`),
    the derived owner is `None`. Treating that as "owned by nobody" would make the
    keyring + member docs permanently unwritable by EVERYONE — a squat-and-brick
    DoS on a predictable room id. Instead an unparseable keyring is treated as "no
    owner established yet" (TOFU stays open), so the legitimate owner's *valid*
    keyring write still lands and ownership transfers to it. This is a recoverable
    DoS, not a hardening: a spammer can keep the window open, but the owner's valid
    write wins the moment it lands.
    """
    room = "edge-brick"
    # Stranger wins the create race with a garbage (non-keyring) document.
    stranger = bootstrap_root_identity("edge-brick-stranger")
    s_cap = mint_device_cap(
        stranger.device["edPriv"], stranger.device["edPub"], _sub(stranger), member_scope(room, True),
    )
    s_client = sdk(s_cap, stranger.device["edPriv"])
    await s_client.push(keyring_push(room), {"garbage": True}, None)  # 200 — TOFU lets the first writer through

    # The real owner can still establish the room: a VALID keyring write lands,
    # overwriting the unparseable squat, and ownership transfers to the owner.
    owner = bootstrap_root_identity("edge-brick-owner")
    o_cap = mint_device_cap(owner.device["edPriv"], owner.device["edPub"], _sub(owner), owner_scope())
    o_client = sdk(o_cap, owner.device["edPriv"])
    cur = await o_client.pull(keyring_pull(room))
    keyring, _cek = create_keyring(owner.device["edPriv"], owner.device["edPub"], [owner.device["kemPub"]])
    await o_client.push(keyring_push(room), keyring.to_dict(), cur.hash or None)  # 200 — recovery, not 403

    # Ownership is now firmly the owner's: the stranger can no longer rotate it.
    listing = await list_recipients(o_client, keyring_name(room), trusted_adders=[owner.device["edPub"]])
    assert owner.device["kemPub"] in {r["subKem"] for r in listing["recipients"]}
    evil_kr, _ = create_keyring(stranger.device["edPriv"], stranger.device["edPub"], [stranger.device["kemPub"]])
    cur2 = await s_client.pull(keyring_pull(room))
    with pytest.raises(StarfishHttpError) as exc:
        await s_client.push(keyring_push(room), evil_kr.to_dict(), cur2.hash)
    assert exc.value.status == 403


async def test_member_directory_squat_before_keyring_is_evicted_by_the_owner(sdk):
    """A members-dir squat written before any keyring exists is recoverable.

    With no keyring yet, the enricher's TOFU branch grants `chat:owner` to the
    first writer, so a stranger CAN seed `chatmembers/rooms/X/_members` for a room
    that has no keyring (pinned). But ownership is anchored to the keyring: once the
    real owner creates the keyring, the stranger loses `chat:owner` (403 on further
    roster writes) and the owner overwrites the squatted directory.
    """
    room = "edge-msquat"
    stranger = bootstrap_root_identity("edge-msquat-stranger")
    s_cap = mint_device_cap(stranger.device["edPriv"], stranger.device["edPub"], _sub(stranger), owner_scope())
    s_client = sdk(s_cap, stranger.device["edPriv"])
    await s_client.push(members_push(room), {"v": 1, "entries": [{"label": "ghost"}]}, None)  # 200 — TOFU squat

    owner = bootstrap_root_identity("edge-msquat-owner")
    o_cap = mint_device_cap(owner.device["edPriv"], owner.device["edPub"], _sub(owner), owner_scope())
    o_client = sdk(o_cap, owner.device["edPriv"])
    cur = await o_client.pull(keyring_pull(room))
    keyring, _cek = create_keyring(owner.device["edPriv"], owner.device["edPub"], [owner.device["kemPub"]])
    await o_client.push(keyring_push(room), keyring.to_dict(), cur.hash or None)  # owner now owns the room

    # The stranger is no longer the owner → roster writes are refused.
    md = await s_client.pull(members_pull(room))
    with pytest.raises(StarfishHttpError) as exc:
        await s_client.push(members_push(room), {"v": 1, "entries": [{"label": "ghost2"}]}, md.hash)
    assert exc.value.status == 403

    # The owner overwrites the squatted roster (clears the ghost entry).
    await o_client.push(members_push(room), {"v": 1, "entries": []}, md.hash)


async def test_owner_role_survives_keyring_epoch_rotation(sdk):
    """Ownership is anchored to epoch-1 genesis, so it survives key rotations.

    The enricher derives the owner from `epochs["1"].wrappedKeys[0].addedBy`. After
    the owner rotates the keyring (a new current epoch), that genesis adder is
    unchanged, so the owner keeps `chat:owner` and can still manage the keyring +
    member directory.
    """
    room = "edge-rotate-own"
    owner = await _setup_owner(sdk, room=room)
    kr_res = await owner.client.pull(keyring_pull(room))
    rotated, _cek = rotate_epoch(
        Keyring.from_dict(kr_res.data),
        owner.creds.device["edPriv"], owner.creds.device["edPub"], [owner.creds.device["kemPub"]],
    )
    await owner.client.push(keyring_push(room), rotated.to_dict(), kr_res.hash)  # 200 — still owner post-rotation

    # Ownership intact: the owner can still write the member directory after rotating.
    md = await owner.client.pull(members_pull(room))
    await owner.client.push(members_push(room), {"v": 1, "entries": []}, md.hash)  # 200


async def test_owner_role_survives_self_eviction_from_the_keyring(sdk):
    """`chat:owner` (an identity/cap role) is decoupled from keyring membership.

    The owner rotates the keyring to a recipient set that EXCLUDES its own KEM key
    (self-eviction — the owner can no longer DECRYPT new content). But ownership is
    derived from the unchanged epoch-1 genesis adder, so the owner KEEPS `chat:owner`
    and can still administer the keyring/roster. Pins the asymmetry: losing read
    access (keyring membership) does not cost write authority (the owner role).
    """
    room = "edge-selfevict"
    owner = await _setup_owner(sdk, room=room)
    other = bootstrap_root_identity("edge-selfevict-other")
    kr_res = await owner.client.pull(keyring_pull(room))
    rotated, _cek = rotate_epoch(  # new epoch's recipients = {other}, NOT the owner
        Keyring.from_dict(kr_res.data),
        owner.creds.device["edPriv"], owner.creds.device["edPub"], [other.device["kemPub"]],
    )
    await owner.client.push(keyring_push(room), rotated.to_dict(), kr_res.hash)  # 200 — owner role survives

    # The owner is no longer a recipient of the current epoch → cannot build a decryptor.
    fresh = Keyring.from_dict((await owner.client.pull(keyring_pull(room))).data)
    with pytest.raises(Exception):
        create_keyring_encryptor(
            fresh, owner.creds.device["kemPub"], owner.creds.device["kemPriv"],
            trusted_adders=[owner.creds.device["edPub"]],
        )
    # … yet it still administers the roster — the owner role is intact.
    md = await owner.client.pull(members_pull(room))
    await owner.client.push(members_push(room), {"v": 1, "entries": []}, md.hash)  # 200


async def test_revoking_the_owners_own_cap_overrides_the_surviving_owner_role(sdk, http):
    """Self-eviction keeps the owner role; revoking the owner's cap is what locks it out.

    Two independent layers gate an owner: the `chat:owner` enricher role (anchored to the
    keyring's epoch-1 genesis) and the cap-cert itself. This composes the two cases tested
    separately — self-evicting from the keyring costs decryption but NOT the owner role
    (the owner still administers the room), while revoking the owner's own cap
    (compromised-device incident response) finally removes write authority: the resolver
    rejects the request 401 *before* the enricher ever runs. Pins that revocation is the
    kill-switch, evaluated ahead of the owner-role grant.
    """
    room = "edge-ownerrevoke"
    creds = bootstrap_root_identity("edge-ownerrevoke")
    cap = mint_device_cap(creds.device["edPriv"], creds.device["edPub"], _sub(creds), owner_scope())
    client = sdk(cap, creds.device["edPriv"])
    keyring, _cek = create_keyring(creds.device["edPriv"], creds.device["edPub"], [creds.device["kemPub"]])
    await client.push(keyring_push(room), keyring.to_dict(), None)  # TOFU: establishes ownership
    md = await client.pull(members_pull(room))
    await client.push(members_push(room), {"v": 1, "entries": []}, md.hash)  # owner role → 200

    # Self-evict: rotate the keyring to a recipient set that excludes the owner.
    other = bootstrap_root_identity("edge-ownerrevoke-other")
    kr = await client.pull(keyring_pull(room))
    rotated, _ = rotate_epoch(
        Keyring.from_dict(kr.data), creds.device["edPriv"], creds.device["edPub"], [other.device["kemPub"]],
    )
    await client.push(keyring_push(room), rotated.to_dict(), kr.hash)  # still 200 — owner role survives self-eviction
    md2 = await client.pull(members_pull(room))
    await client.push(members_push(room), {"v": 1, "entries": []}, md2.hash)  # 200 — still administers

    # Revoke the owner's OWN cap (issuer == the root that self-signed it).
    rev = _sign_revocation_list(
        creds.device["edPub"], creds.device["edPriv"],
        [{"sub": cap["sub"], "nonce": cap["nonce"]}], generation=1,
    )
    assert (await http.post("/revocations", json=rev)).status_code == 200

    # The surviving owner role no longer helps — the cap is rejected before the enricher.
    with pytest.raises(StarfishHttpError) as exc:
        await client.pull(members_pull(room))
    assert exc.value.status == 401


async def test_concurrent_member_adds_do_not_lose_an_update(sdk):
    """Two roster adds racing on the same baseHash both land — neither is silently dropped.

    `add_member_entry` retries on the 409 it gets when a concurrent writer advances the
    directory hash, so two simultaneous invitations resolve to two entries rather than a
    lost update. Pins the optimistic-concurrency retry under an actual `asyncio.gather`
    race (the in-process ASGI loop interleaves the two pull→push cycles).
    """
    room = "edge-concurrent-roster"
    owner = await _setup_owner(sdk, room=room)

    def _cap_for(tag: str):
        who = bootstrap_root_identity(tag)
        return mint_member_cap(
            owner.creds.device["edPriv"], owner.creds.device["edPub"],
            {"edPubHex": who.device["edPub"], "kemPubHex": who.device["kemPub"], "userIdHex": who.user_id},
            "chat", member_scope(room, True),
        )

    bob_cap, carol_cap = _cap_for("edge-concurrent-bob"), _cap_for("edge-concurrent-carol")
    before = len(await list_members(owner.client, members_name(room)))
    await asyncio.gather(
        add_member_entry(owner.client, members_name(room), bob_cap, label="bob"),
        add_member_entry(owner.client, members_name(room), carol_cap, label="carol"),
    )
    after = await list_members(owner.client, members_name(room))
    assert len(after) == before + 2  # the retry resolved the 409 — neither add was lost


async def test_rendezvous_slot_can_be_wiped_by_anyone_who_learns_the_id(sdk):
    """The public rendezvous slot is overwritable → a known id can be DoS'd.

    PINS a documented availability limit: `_pairing/{id}` is `public` read+write so
    the credential-less new device can fetch its bundle. Anyone who learns the
    rendezvous id (e.g. by observing the QR) can overwrite the slot, so a pushed
    PairingBundle can be clobbered before the new device fetches it — a pairing DoS.
    Confidentiality is unaffected (the bundle CEKs are E2E-wrapped and the app pins
    `expectedRootEdPub`); only availability. Mitigated in practice by the unguessable
    16-byte id + short TTL; production SHOULD rate-limit the slot.
    """
    legit = bootstrap_root_identity("edge-rdv-wipe-legit")
    new_device = generate_device_keys()
    parsed = parse_pairing_qr(build_pairing_qr(new_device["edPub"], new_device["kemPub"], owner_scope()))

    # The legitimate root pushes its bundle …
    bundle = assemble_pairing_bundle(
        {"edPriv": legit.device["edPriv"], "edPub": legit.device["edPub"]}, parsed, {},
        AssemblePairingBundleOpts(granted_scope=owner_scope()),
    )
    await push_pairing_bundle(sdk(), parsed.qr_nonce, bundle)
    assert await fetch_pairing_bundle(sdk(), parsed.qr_nonce) is not None  # bundle is there

    # … but anyone who knows the id wipes the public slot (no cap required).
    await clear_pairing_bundle(sdk(), parsed.qr_nonce)

    # The new device now fetches an empty slot → it cannot complete pairing.
    assert await fetch_pairing_bundle(sdk(), parsed.qr_nonce) is None


async def test_rendezvous_slot_is_rate_limited():
    """A flood of overwrites to the public `_pairing/{id}` slot is bounded by a 429.

    Companion to `test_rendezvous_slot_can_be_wiped_by_anyone_who_learns_the_id`: a
    single wipe still works (the slot is public by design), but the per-collection
    `rate_limit` now caps a *flood* — the documented availability mitigation. Driven
    against a FRESH router built from the real `server.config`, so the assertion
    exercises the shipped wiring while keeping the limiter's in-memory buckets
    isolated: the limiter keys anonymous writes by client IP, so flooding the shared
    `server.app` would otherwise leak 429s into the other rendezvous tests.
    """
    from fastapi import FastAPI
    from starfish_sdk import StarfishClient
    from starfish_server.router import SyncRouterOptions, create_sync_router

    rl = next(c for c in server.config.collections if c.name == "pairingrendezvous").rate_limit
    assert rl is not None and rl.max_requests is not None  # the slot opts into rate limiting
    limit = rl.max_requests

    router = create_sync_router(
        SyncRouterOptions(
            store=server.store,
            config=server.config,
            role_resolver=server.role_resolver,
            role_enricher=server.make_owner_role_enricher(server.store),
        )
    )
    app = FastAPI()
    app.include_router(router)

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url=BASE_URL) as raw:
        client = StarfishClient(BASE_URL, cap_provider=None, client=raw)  # anonymous (public slot)
        statuses: list[int] = []
        for i in range(limit + 5):
            # A fresh slot id each iteration → every write is a clean create (no blind-
            # overwrite 409); the per-collection limiter still buckets them by client IP.
            try:
                await client.push(f"/push/_pairing/ratelimit-probe-{i}", {"i": i}, None)
                statuses.append(200)
            except StarfishHttpError as exc:
                statuses.append(exc.status)
                if exc.status == 429:
                    break

    assert statuses[0] == 200  # writes under the cap are allowed …
    assert 429 in statuses, f"expected a 429 within {limit + 5} writes, got {statuses}"  # … the flood is capped


# ══════════════════════════════════════════════════════════════════════════════
# ROUND R2 — the two membership layers (cap vs keyring) and their seams
#
# Server authorization (cap) and decryption ability (keyring recipient) are
# INDEPENDENT facts. These pin both directions of the decoupling, the operational
# footgun it creates (removal is two steps), per-user entitlement confidentiality,
# and the rendezvous bundle↔nonce binding.
# ══════════════════════════════════════════════════════════════════════════════
async def test_member_cap_without_keyring_entry_can_read_ciphertext_but_not_decrypt(sdk):
    """An invited member (has a cap) NOT added to the keyring reads ciphertext but
    cannot decrypt — the two grants are independent.

    Inviting is two steps: mint a member cap (server access) AND add the member to
    the keyring (decryption). A half-completed invite — cap issued, keyring add
    skipped — leaves the member able to pull the encrypted blob but unable to read
    it. Pins that holding a valid member cap is NOT keyring membership.
    """
    room = "edge-capnokr"
    owner = await _setup_owner(sdk, room=room)
    s = owner.sync()
    await s.pull()
    await s.push({**s.data, "messages": [*(s.data.get("messages") or []), _msg("members-only", owner.creds, "Alice")]})

    bob = bootstrap_root_identity("edge-capnokr-bob")
    bob_cap = mint_member_cap(
        owner.creds.device["edPriv"], owner.creds.device["edPub"],
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        "chat", member_scope(room, False),  # read-only member, NOT added to the keyring
    )
    bob_client = sdk(bob_cap, bob.device["edPriv"])
    blob = await bob_client.pull(room_pull(room))  # 200 — the cap grants server access
    assert isinstance(blob.data, dict) and blob.data.get("_encrypted")

    kr = await bob_client.pull(keyring_pull(room))
    with pytest.raises(Exception):  # no wrapped key for Bob → cannot build a decryptor
        create_keyring_encryptor(
            Keyring.from_dict(kr.data), bob.device["kemPub"], bob.device["kemPriv"],
            trusted_adders=[owner.creds.device["edPub"]],
        )


async def test_keyring_recipient_without_a_cap_cannot_reach_the_room(sdk):
    """Being a keyring recipient grants decryption ability but NO server access.

    The owner adds Bob to the room keyring (he could decrypt, IF he could fetch the
    ciphertext). But Bob holds no cap, so an anonymous request for the room doc is
    refused — `cap:read:chat` is required, and keyring membership is a client-side
    fact invisible to the server's authorization. The layers are independent in this
    direction too.
    """
    room = "edge-krnocap"
    owner = await _setup_owner(sdk, room=room)
    bob = bootstrap_root_identity("edge-krnocap-bob")
    await add_collection_recipient(
        owner.client, keyring_name(room),
        {"subKem": bob.device["kemPub"], "userId": bob.user_id, "label": "bob"}, _adder(owner.creds),
        trusted_adders=[owner.creds.device["edPub"]],
    )
    anon = sdk()  # no cap_provider → anonymous (roles=["public"])
    with pytest.raises(StarfishHttpError) as exc:
        await anon.pull(room_pull(room))
    assert exc.value.status in (401, 403)


async def test_cross_user_entitlements_read_is_denied(sdk, http):
    """User A cannot read user B's entitlements, even with a scope that names B's path.

    Entitlements live at `users/{identity}/entitlements`; the `{identity}` binding is
    enforced against the AUTHENTICATED identity (a device cap resolves to its issuer).
    So A — self-signing a cap whose scope names B's entitlements path — is refused 403:
    the cap-bound identity (A) ≠ the requested path identity (B). Paid-feature state
    stays confidential per-user.
    """
    alice = bootstrap_root_identity("edge-ent-alice")
    bob = bootstrap_root_identity("edge-ent-bob")
    await http.post("/demo/grant", json={"userId": bob.user_id})  # Bob has premium

    snoop_scope = {
        "ops": ["read", "list"],
        "collections": ["entitlements"],
        "paths": [f"users/{bob.user_id}/entitlements"],
    }
    cap = mint_device_cap(alice.device["edPriv"], alice.device["edPub"], _sub(alice), snoop_scope)
    alice_client = sdk(cap, alice.device["edPriv"])
    with pytest.raises(StarfishHttpError) as exc:
        await alice_client.pull(f"/pull/users/{bob.user_id}/entitlements")
    assert exc.value.status == 403


async def test_keyring_removal_alone_does_not_revoke_write_access(sdk, http):
    """Removing a member from the keyring does NOT stop them writing — full eviction
    needs more than a key rotation.

    Bob is a real member: in the member directory AND the keyring. The owner removes
    him from the keyring (forward secrecy: he can't decrypt new content). But he is
    still in the directory and his cap is still valid, so his `chat:member` role is
    intact — he keeps posting (200), clobbering the room with content the others can't
    decrypt. Only after his cap is REVOKED does every request fail (401). Pins the
    operational footgun: keyring rotation ≠ eviction (you must also remove the member
    from the directory and/or revoke the cap).

    A dedicated issuer mints Bob's cap (in the real app the room owner's root is the
    issuer) so the revocation generation stays independent of the session-shared
    revocation store — same convention as the other revocation tests.
    """
    room = "edge-twostep"
    owner = await _setup_owner(sdk, room=room)
    issuer = bootstrap_root_identity("edge-twostep-issuer")
    bob = bootstrap_root_identity("edge-twostep-bob")
    bob_cap = mint_member_cap(
        issuer.device["edPriv"], issuer.device["edPub"],
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        "chat", member_scope(room, True),
    )
    await add_collection_recipient(
        owner.client, keyring_name(room),
        {"subKem": bob.device["kemPub"], "userId": bob.user_id, "label": "bob"}, _adder(owner.creds),
        trusted_adders=[owner.creds.device["edPub"]],
    )
    await add_member_entry(owner.client, members_name(room), bob_cap, label="bob")  # in the roster → chat:member
    bob_client = sdk(bob_cap, bob.device["edPriv"])

    # Owner removes Bob from the keyring (epoch rotates → forward secrecy on reads).
    await remove_recipient(
        owner.client, keyring_name(room), [bob.device["kemPub"]], _adder(owner.creds),
        trusted_adders=[owner.creds.device["edPub"]],
    )

    # Bob's cap is untouched → he can STILL write the room after keyring removal.
    base = await bob_client.pull(room_pull(room))
    bkr, _cek = create_keyring(bob.device["edPriv"], bob.device["edPub"], [bob.device["kemPub"]])
    benc = create_keyring_encryptor(
        bkr, bob.device["kemPub"], bob.device["kemPriv"], trusted_adders=[bob.device["edPub"]],
    )
    await bob_client.push(room_push(room), benc.encrypt({"messages": [{"id": "z", "text": "still-here"}]}), base.hash)  # 200

    # Full eviction: revoke Bob's cap. Now even a read fails 401 (the cap is dead).
    rev = _sign_revocation_list(
        issuer.device["edPub"], issuer.device["edPriv"],
        [{"sub": bob_cap["sub"], "nonce": bob_cap["nonce"]}], generation=1,
    )
    assert (await http.post("/revocations", json=rev)).status_code == 200
    with pytest.raises(StarfishHttpError) as exc:
        await bob_client.pull(room_pull(room))
    assert exc.value.status == 401


async def test_evict_member_blocks_writes_in_one_call(sdk, http):
    """`evict_member({rotate, revoke})` fully evicts in ONE call — the footgun fix.

    Counterpart to `test_keyring_removal_alone_does_not_revoke_write_access`: the lib
    helper revokes the member's cap, rotates them out of the keyring, AND drops their
    directory entry in a single call. After it, the member's next request is **401**
    (cap revoked, not merely 403) and they are gone from both the keyring recipients
    and the member directory. A dedicated issuer keeps the revocation generation
    independent of the session-shared revocation store.
    """
    room = "edge-evict-onecall"
    owner = await _setup_owner(sdk, room=room)
    issuer = bootstrap_root_identity("edge-evict-issuer")
    bob = bootstrap_root_identity("edge-evict-bob")
    bob_cap = mint_member_cap(
        issuer.device["edPriv"], issuer.device["edPub"],
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        "chat", member_scope(room, True),
    )
    await add_collection_recipient(
        owner.client, keyring_name(room),
        {"subKem": bob.device["kemPub"], "userId": bob.user_id, "label": "bob"}, _adder(owner.creds),
        trusted_adders=[owner.creds.device["edPub"]],
    )
    await add_member_entry(owner.client, members_name(room), bob_cap, label="bob")
    bob_client = sdk(bob_cap, bob.device["edPriv"])

    # Bob is a full member (in roster + keyring) → he can write the room.
    base = await bob_client.pull(room_pull(room))
    bkr, _cek = create_keyring(bob.device["edPriv"], bob.device["edPub"], [bob.device["kemPub"]])
    benc = create_keyring_encryptor(
        bkr, bob.device["kemPub"], bob.device["kemPriv"], trusted_adders=[bob.device["edPub"]],
    )
    await bob_client.push(room_push(room), benc.encrypt({"messages": [{"id": "a", "text": "hi"}]}), base.hash)  # 200

    # One call does all three steps. submit_revocation POSTs the signed list.
    async def _submit(rev_list: dict) -> None:
        assert (await http.post("/revocations", json=rev_list)).status_code == 200

    result = await evict_member(
        owner.client,
        keyring_collection=keyring_name(room),
        members_collection=members_name(room),
        member={"sub": bob_cap["sub"], "nonce": bob_cap["nonce"], "exp": bob_cap["exp"], "subKem": bob.device["kemPub"]},
        adder=_adder(owner.creds),
        trusted_adders=[owner.creds.device["edPub"]],
        iss_ed_pub_hex=issuer.device["edPub"],
        iss_ed_priv_hex=issuer.device["edPriv"],
        generation=1,
        submit_revocation=_submit,
        rotate=True,
        revoke=True,
    )
    assert result["revoked"] is True and result.get("newEpoch")

    # Bob's cap is revoked → his next request is 401 (full eviction, not just 403).
    with pytest.raises(StarfishHttpError) as exc:
        await bob_client.pull(room_pull(room))
    assert exc.value.status == 401

    # … and he is gone from both the keyring recipients and the member directory.
    recips = await list_recipients(owner.client, keyring_name(room), trusted_adders=[owner.creds.device["edPub"]])
    assert bob.device["kemPub"] not in {r["subKem"] for r in recips["recipients"]}
    members = await list_members(owner.client, members_name(room))
    assert all(m.get("nonce") != bob_cap["nonce"] for m in members)


async def test_pairing_bundle_is_bound_to_its_rendezvous_nonce(sdk):
    """A bundle assembled for one QR nonce cannot be installed against another.

    `install_pairing_bundle` verifies the bundle's `qrNonce` equals the device's
    `expected_qr_nonce`. So a bundle captured from slot A and replayed at a device
    expecting slot B's nonce is rejected — the bundle is bound to the rendezvous it
    answers, foreclosing a cross-slot replay.
    """
    root = bootstrap_root_identity("edge-rdv-bind-root")
    dev_a = generate_device_keys()
    dev_b = generate_device_keys()
    qr_a = parse_pairing_qr(build_pairing_qr(dev_a["edPub"], dev_a["kemPub"], owner_scope()))
    qr_b = parse_pairing_qr(build_pairing_qr(dev_b["edPub"], dev_b["kemPub"], owner_scope()))

    bundle_a = assemble_pairing_bundle(
        {"edPriv": root.device["edPriv"], "edPub": root.device["edPub"]}, qr_a, {},
        AssemblePairingBundleOpts(granted_scope=owner_scope()),
    )
    # Installing bundle_a while expecting a DIFFERENT slot's nonce is rejected.
    with pytest.raises(Exception):
        install_pairing_bundle(
            bundle_a, dev_a, expected_root_ed_pub=root.device["edPub"], expected_qr_nonce=qr_b.qr_nonce,
        )
    # Sanity: the matching nonce installs fine.
    ok = install_pairing_bundle(
        bundle_a, dev_a, expected_root_ed_pub=root.device["edPub"], expected_qr_nonce=qr_a.qr_nonce,
    )
    assert ok.credentials.user_id == root.user_id


# ══════════════════════════════════════════════════════════════════════════════
# ROUND R3 — the live feed, scope-gate precision, and content hygiene
#
# Deeper corners: what the deliberately-open /events stream actually discloses,
# whether a universal path glob can widen a cap past its COLLECTION role, keyring
# confidentiality across rooms, server value-sanitization (XSS responsibility), and
# audit attribution for un-authenticated writes.
# ══════════════════════════════════════════════════════════════════════════════
async def test_events_feed_broadcasts_only_metadata_never_document_content(sdk):
    """The unauthenticated /events feed broadcasts metadata only — no content.

    A chat push fans a queue message out to every SSE subscriber. The app's
    QueueConfig sets `include_params=True` but NOT `include_body`, so the broadcast
    carries only {collection, hash, timestamp, params:{roomId}} — never the document
    body, not even the ciphertext envelope. An eavesdropper on the open stream learns
    THAT a room changed and WHICH room (the documented metadata leak) but neither the
    plaintext nor the encrypted blob. We tap `server.sse_subscribers` directly to read
    exactly what a subscriber would receive.
    """
    room = "edge-sse"
    owner = await _setup_owner(sdk, room=room)
    sink: asyncio.Queue[str] = asyncio.Queue(maxsize=8)
    server.sse_subscribers.add(sink)
    try:
        s = owner.sync()
        await s.pull()
        await s.push({**s.data, "messages": [*(s.data.get("messages") or []), _msg("DO-NOT-LEAK-THIS", owner.creds, "Alice")]})
        raw = await asyncio.wait_for(sink.get(), timeout=2.0)
    finally:
        server.sse_subscribers.discard(sink)

    event = json.loads(raw)
    assert event["collection"] == "chat"
    assert event["params"]["roomId"] == room  # metadata: which room changed
    assert "body" not in event                # NO document content is broadcast …
    assert "DO-NOT-LEAK-THIS" not in raw      # … so the plaintext never leaves the client
    assert "_encrypted" not in raw            # … and not even the ciphertext envelope


async def test_events_sse_over_http_metadata_only(sdk):
    """``GET /events`` fans out metadata only on the bus HTTP subscribers share.

    A concurrent in-process HTTP stream read plus async cap-signed push deadlocks
    under httpx ``ASGITransport``, so this pins the ``/events`` route registration
    and the queuing → ``sse_subscribers`` payload (the same path ``events()`` uses).
    """
    room = "edge-sse-http"
    owner = await _setup_owner(sdk, room=room)
    assert any(getattr(r, "path", None) == "/events" for r in server.app.routes)

    sink: asyncio.Queue[str] = asyncio.Queue(maxsize=8)
    server.sse_subscribers.add(sink)
    try:
        s = owner.sync()
        await s.pull()
        await s.push(
            {**s.data, "messages": [*(s.data.get("messages") or []), _msg("SSE-HTTP-LEAK", owner.creds, "Alice")]},
        )
        raw = await asyncio.wait_for(sink.get(), timeout=2.0)
    finally:
        server.sse_subscribers.discard(sink)

    event = json.loads(raw)
    assert event["collection"] == "chat"
    assert event["params"]["roomId"] == room
    assert "body" not in event
    assert "SSE-HTTP-LEAK" not in raw
    assert "_encrypted" not in raw


async def test_universal_path_glob_does_not_cross_collection_role_boundaries(sdk):
    """A `**` path glob widens PATHS, not the synthesized COLLECTION role.

    A device cap scoped to collection `chat` with `paths:["**"]` matches every
    request path — but the resolver synthesizes only `cap:<op>:chat`, never
    `cap:read:entitlements`. So even though the universal glob "covers" the
    entitlements path (and the `{identity}` binding is satisfied — it's the caller's
    OWN doc), the read is refused 403: collection-role and path-scope are independent
    gates and BOTH must pass.
    """
    user = bootstrap_root_identity("edge-uglob")
    wide = {"ops": ["read", "list", "write"], "collections": ["chat"], "paths": ["**"]}
    cap = mint_device_cap(user.device["edPriv"], user.device["edPub"], _sub(user), wide)
    client = sdk(cap, user.device["edPriv"])
    with pytest.raises(StarfishHttpError) as exc:
        await client.pull(f"/pull/users/{user.user_id}/entitlements")
    assert exc.value.status == 403


async def test_member_cap_cannot_read_another_rooms_keyring(sdk):
    """A member scoped to room X cannot read room Y's keyring → 403.

    Member caps are room-scoped (`chatkeyring/rooms/{X}/_keyring`). A request for a
    DIFFERENT room's keyring is outside `scope.paths` and is refused, so a member of
    one room cannot harvest another room's wrapped CEKs.
    """
    owner_x = await _setup_owner(sdk, room="edge-roomx")
    await _setup_owner(sdk, passphrase="edge-roomy-owner", room="edge-roomy")
    bob = bootstrap_root_identity("edge-xroom-bob")
    bob_cap = mint_member_cap(
        owner_x.creds.device["edPriv"], owner_x.creds.device["edPub"],
        {"edPubHex": bob.device["edPub"], "kemPubHex": bob.device["kemPub"], "userIdHex": bob.user_id},
        "chat", member_scope("edge-roomx", True),  # scoped to room X only
    )
    bob_client = sdk(bob_cap, bob.device["edPriv"])
    await bob_client.pull(keyring_pull("edge-roomx"))  # 200 — own room
    with pytest.raises(StarfishHttpError) as exc:
        await bob_client.pull(keyring_pull("edge-roomy"))  # 403 — different room
    assert exc.value.status == 403


async def test_profile_pseudo_is_stored_verbatim_so_the_client_must_escape_it(sdk):
    """The server stores a profile pseudo byte-for-byte — no HTML sanitization.

    Starfish is a dumb store: it strips dangerous OBJECT KEYS (prototype-pollution
    vectors) but does NOT sanitize VALUES. A pseudo containing markup is persisted
    verbatim and served back to every reader (profile reads are public), so the
    FRONTEND must escape pseudos on render. Pins that XSS-safety is a rendering
    responsibility, not a server guarantee. NOTE: this asserts the SERVER side only
    (verbatim storage); verifying the frontend actually escapes on render is the
    Playwright spec's job (not run by default) — out of scope for this suite.
    """
    user = bootstrap_root_identity("edge-xss")
    cap = mint_device_cap(user.device["edPriv"], user.device["edPub"], _sub(user), account_scope(user.user_id))
    client = sdk(cap, user.device["edPriv"])
    payload = "<img src=x onerror=alert(1)>"
    await client.push(f"/push/user/{user.user_id}/profile", {"v": 1, "pseudo": payload}, None)
    back = await client.pull(f"/pull/user/{user.user_id}/profile")
    assert back.data["pseudo"] == payload  # stored & served verbatim — the client must escape


async def test_anonymous_public_write_is_audited_as_anonymous(sdk, http):
    """An anonymous write to a public collection is audited with identity "anonymous".

    The rendezvous slot is `public` write, so a credential-less device pushes without
    a cap. The audit logger still records the push — attributed to "anonymous" — so
    even un-authenticated activity on the open slots is observable via /audit.
    """
    legit = bootstrap_root_identity("edge-anon-audit")
    new_device = generate_device_keys()
    parsed = parse_pairing_qr(build_pairing_qr(new_device["edPub"], new_device["kemPub"], owner_scope()))
    bundle = assemble_pairing_bundle(
        {"edPriv": legit.device["edPriv"], "edPub": legit.device["edPub"]}, parsed, {},
        AssemblePairingBundleOpts(granted_scope=owner_scope()),
    )
    await push_pairing_bundle(sdk(), parsed.qr_nonce, bundle)  # anonymous public write

    audit = (await http.get("/audit")).json()
    rdv = [e for e in audit if e["collection"] == "pairingrendezvous"]
    assert rdv and any(e["identity"] == "anonymous" and e["success"] for e in rdv)


# ══════════════════════════════════════════════════════════════════════════════
# ROUND R4 — collection size limits (and a body that slips past them)
#
# Every collection declares its own `max_body_bytes`. These pin that each ceiling
# bites independently of the resolver's 256 KB pre-auth guard — and surface a body
# that passes the size guard yet still crashes the handler.
# ══════════════════════════════════════════════════════════════════════════════
async def test_deeply_nested_body_is_rejected_not_crashes(sdk, http):
    """A deeply-nested JSON body is rejected 400 — the DoS is fixed.

    The pre-auth guard checks Content-Length only, and the per-request signature
    covers the body BYTES, so a small (~30 KB) but deeply-nested document passes both
    the resolver guard AND the per-collection limit. The push handler used to parse it
    with an unwrapped `await request.json()` + recursive `deep_sanitize`, raising an
    unhandled `RecursionError` (→ HTTP 500). It now parses defensively (catching the
    overflow) and enforces a hard nesting bound (`json_depth_within`) → **400**, so the
    document never reaches the recursive sanitizer.
    """
    user = bootstrap_root_identity("edge-deep")
    scope = {"ops": ["read", "list", "write"], "collections": ["devices"], "paths": [f"users/{user.user_id}/_devices"]}
    cap = mint_device_cap(user.device["edPriv"], user.device["edPub"], _sub(user), scope)
    cap_b64 = base64.b64encode(stable_stringify(cap).encode("utf-8")).decode("ascii")
    path = f"/push/users/{user.user_id}/_devices"
    depth = 5_000  # well past CPython's default recursion limit (1000); ~30 KB on the wire
    nested = '{"a":' * depth + "1" + "}" * depth
    body = ('{"data":' + nested + ',"baseHash":null}').encode("utf-8")
    sig = sign_request("POST", path, body, user.device["edPriv"], host="testserver")
    headers = {
        "Authorization": f"Cap {cap_b64}", "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": str(sig.ts), "X-Starfish-Nonce": sig.nonce,
        "Content-Type": "application/json",
    }
    resp = await http.post(path, content=body, headers=headers)
    assert resp.status_code == 400  # bounded, not a 500/crash


async def test_deeply_nested_body_at_the_exact_depth_boundary(sdk, http):
    """The nesting guard is an inclusive ceiling at exactly MAX_DOC_DEPTH, end-to-end.

    The companion test above proves a pathological 5 000-deep body is bounded; this
    pins the off-by-one through the real push path. The handler runs the guard on the
    whole envelope `{"data": <nested>, "baseHash": null}`, so a `data` nested
    `MAX_DOC_DEPTH - 1` deep sits at the ceiling and is accepted (200), while one level
    deeper trips it (400) — before the recursive sanitizer ever runs.
    """
    from starfish_server.router.helpers import MAX_DOC_DEPTH

    user = bootstrap_root_identity("edge-deep-boundary")
    scope = {"ops": ["read", "list", "write"], "collections": ["devices"], "paths": [f"users/{user.user_id}/_devices"]}
    cap = mint_device_cap(user.device["edPriv"], user.device["edPub"], _sub(user), scope)
    cap_b64 = base64.b64encode(stable_stringify(cap).encode("utf-8")).decode("ascii")
    path = f"/push/users/{user.user_id}/_devices"

    async def _push_data_nested(levels: int) -> int:
        nested = '{"a":' * levels + "1" + "}" * levels
        body = ('{"data":' + nested + ',"baseHash":null}').encode("utf-8")
        sig = sign_request("POST", path, body, user.device["edPriv"], host="testserver")
        headers = {
            "Authorization": f"Cap {cap_b64}", "X-Starfish-Sig": sig.sig,
            "X-Starfish-Ts": str(sig.ts), "X-Starfish-Nonce": sig.nonce,
            "Content-Type": "application/json",
        }
        resp = await http.post(path, content=body, headers=headers)
        return resp.status_code

    # data nested (MAX_DOC_DEPTH - 1) → envelope depth == MAX_DOC_DEPTH → accepted.
    assert await _push_data_nested(MAX_DOC_DEPTH - 1) == 200
    # one level deeper → envelope exceeds the ceiling → rejected before sanitizing.
    assert await _push_data_nested(MAX_DOC_DEPTH) == 400


async def test_keyring_write_respects_its_64kb_ceiling(sdk):
    """The `chatkeyring` collection enforces its own 64 KB limit (below the 256 KB guard).

    A keyring body padded just under 64 KB is accepted; one just over is rejected 413
    by the per-collection check even though it is far under the resolver's 256 KB
    pre-auth guard. The owner is authorized (`chat:owner`), so this isolates the SIZE
    gate from the auth gate.
    """
    room = "edge-krsize"
    owner = await _setup_owner(sdk, room=room)
    base = (await owner.client.pull(keyring_pull(room))).hash

    # A keyring doc whose serialized body is comfortably under 64 KB lands.
    small = {"v": 1, "epochs": {}, "pad": "x" * 40_000}
    await owner.client.push(keyring_push(room), small, base)  # 200

    # One padded past 64 KB (still well under the 256 KB guard) is 413.
    big = {"v": 1, "epochs": {}, "pad": "x" * 70_000}
    cur = (await owner.client.pull(keyring_pull(room))).hash
    with pytest.raises(StarfishHttpError) as exc:
        await owner.client.push(keyring_push(room), big, cur)
    assert exc.value.status == 413


async def test_member_directory_write_respects_its_128kb_ceiling(sdk):
    """The `chatmembers` collection enforces its 128 KB limit.

    A member directory padded past 128 KB (but under the 256 KB pre-auth guard) is
    rejected 413 by the per-collection check; a body under the ceiling lands.
    """
    room = "edge-msize"
    owner = await _setup_owner(sdk, room=room)
    base = (await owner.client.pull(members_pull(room))).hash
    await owner.client.push(members_push(room), {"v": 1, "entries": [], "pad": "y" * 100_000}, base)  # 200

    cur = (await owner.client.pull(members_pull(room))).hash
    with pytest.raises(StarfishHttpError) as exc:
        await owner.client.push(members_push(room), {"v": 1, "entries": [], "pad": "y" * 140_000}, cur)
    assert exc.value.status == 413


# ══════════════════════════════════════════════════════════════════════════════
# ROUND R5 — the batch surface and "self" (per-identity) rights
#
# `/batch/pull` is the only multi-document endpoint (no batch push/list). These pin
# that it cannot side-step scope or the `{identity}` self-binding, and that a cap
# only ever reaches its OWN `user/{identity}/…` namespace — including the fact that
# an attacker cannot forge another identity to cross that boundary.
# ══════════════════════════════════════════════════════════════════════════════
async def test_batch_pull_enforces_cap_scope_per_resolved_key(http):
    """`/batch/pull` honors a cap's `scope.paths` per RESOLVED key.

    The cap resolver can't path-bind a `/batch/pull` request (its URL names no
    storage path), so the batch handler re-checks each collection's resolved key
    against `scope.paths`. A cap scoped to room "room-a" reads room-a but is
    Forbidden on room-b — batch is not a way around the per-path scope. (There is
    no batch-push/list, so the multi-document surface stays read-only and gated.)
    """
    user = bootstrap_root_identity("edge-batch")
    cap = mint_device_cap(
        user.device["edPriv"], user.device["edPub"], _sub(user), member_scope("room-a", False),
    )

    def _batch_path(room: str) -> str:
        q = quote(json.dumps({"chat": [{"roomId": room}]}, separators=(",", ":")))
        return f"/batch/pull?collections=chat&params={q}"

    # In-scope room → reachable (empty doc, but NOT an error).
    p_ok = _batch_path("room-a")
    r_ok = await http.get(p_ok, headers=_signed_get_headers(cap, user.device["edPriv"], p_ok))
    assert r_ok.status_code == 200
    assert "error" not in r_ok.json()["collections"]["chat"][0]

    # Out-of-scope room → Forbidden, never data.
    p_no = _batch_path("room-b")
    r_no = await http.get(p_no, headers=_signed_get_headers(cap, user.device["edPriv"], p_no))
    assert r_no.status_code == 200
    cols = r_no.json()["collections"]
    assert cols["chat"][0]["error"] == "Forbidden"
    assert "data" not in cols["chat"][0]


async def test_batch_pull_cannot_exfiltrate_another_users_namespace(sdk, http):
    """Batch pull cannot read another user's private namespace.

    Two guards: (1) an anonymous caller has no identity to auto-fill `{identity}`,
    so each `{identity}`-templated collection reports a missing param — never data.
    (2) A cap that supplies SOMEONE ELSE's identity resolves a key outside its own
    `scope.paths`, so the batch handler returns Forbidden. Batch is not a
    side-channel around the `{identity}` self-binding.
    """
    alice = bootstrap_root_identity("edge-batch-alice")
    acap = mint_device_cap(alice.device["edPriv"], alice.device["edPub"], _sub(alice), account_scope(alice.user_id))
    await sdk(acap, alice.device["edPriv"]).push(
        f"/push/user/{alice.user_id}/profile", {"v": 1, "pseudo": "Alice"}, None,
    )  # a real profile doc now exists
    bob = bootstrap_root_identity("edge-batch-bob")

    # (1) Anonymous batch — no identity to bind, so {identity} collections report missing param.
    resp = await http.get("/batch/pull?collections=profile,entitlements,devices")  # anonymous
    assert resp.status_code == 200
    cols = resp.json()["collections"]
    for name in ("profile", "entitlements", "devices"):
        assert "data" not in cols[name][0]  # never returns a user's document

    # (2) Alice's cap supplying BOB's identity → resolved key is outside Alice's
    # scope.paths → Forbidden, no data leak.
    q = quote(json.dumps({"entitlements": [{"identity": bob.user_id}]}, separators=(",", ":")))
    p = f"/batch/pull?collections=entitlements&params={q}"
    r2 = await http.get(p, headers=_signed_get_headers(acap, alice.device["edPriv"], p))
    assert r2.status_code == 200
    c2 = r2.json()["collections"]["entitlements"][0]
    assert c2.get("error") == "Forbidden"
    assert "data" not in c2


async def test_self_namespace_is_bound_to_the_authenticated_identity(sdk, http):
    """A cap reaches only its OWN `user/{identity}/…` namespace.

    Positive: Alice writes her own profile and reads her own (granted) entitlements.
    Negative: a self-signed cap whose scope NAMES Bob's profile / entitlements /
    devices paths is 403 on each — the `{identity}` path param must equal the
    authenticated identity (Alice), so "self" is the only namespace any cap can touch.
    """
    alice = bootstrap_root_identity("edge-self-alice")
    bob = bootstrap_root_identity("edge-self-bob")
    await http.post("/demo/grant", json={"userId": alice.user_id})

    # Positive — Alice's own namespace works.
    acap = mint_device_cap(alice.device["edPriv"], alice.device["edPub"], _sub(alice), account_scope(alice.user_id))
    aclient = sdk(acap, alice.device["edPriv"])
    await aclient.push(f"/push/user/{alice.user_id}/profile", {"v": 1, "pseudo": "Alice"}, None)  # 200
    ent = await aclient.pull(f"/pull/users/{alice.user_id}/entitlements")
    assert "premium" in (ent.data.get("features") or [])

    # Negative — a self-signed cap that NAMES Bob's paths is 403 on each self-collection.
    bob_profile = {"ops": ["write"], "collections": ["profile"], "paths": [f"user/{bob.user_id}/profile"]}
    with pytest.raises(StarfishHttpError) as e1:
        await sdk(mint_device_cap(alice.device["edPriv"], alice.device["edPub"], _sub(alice), bob_profile),
                  alice.device["edPriv"]).push(f"/push/user/{bob.user_id}/profile", {"v": 1, "pseudo": "x"}, None)
    assert e1.value.status == 403

    bob_ent = {"ops": ["read"], "collections": ["entitlements"], "paths": [f"users/{bob.user_id}/entitlements"]}
    with pytest.raises(StarfishHttpError) as e2:
        await sdk(mint_device_cap(alice.device["edPriv"], alice.device["edPub"], _sub(alice), bob_ent),
                  alice.device["edPriv"]).pull(f"/pull/users/{bob.user_id}/entitlements")
    assert e2.value.status == 403

    bob_dev = {"ops": ["read"], "collections": ["devices"], "paths": [f"users/{bob.user_id}/_devices"]}
    with pytest.raises(StarfishHttpError) as e3:
        await sdk(mint_device_cap(alice.device["edPriv"], alice.device["edPub"], _sub(alice), bob_dev),
                  alice.device["edPriv"]).pull(f"/pull/users/{bob.user_id}/_devices")
    assert e3.value.status == 403


async def test_forged_owner_identity_cannot_seize_the_owner_role(sdk):
    """An attacker cannot claim the owner's userId to defeat owner-binding.

    Owner-binding gates keyring/roster writes on `auth.identity == <room owner>`, and
    `auth.identity` is the cap's `issUserId`/`subUserId` — each REQUIRED to equal
    sha256(key)[:16], checked independently of the signature. So an attacker who edits
    a self-signed device cap to claim the OWNER's userId (keeping their own `iss` key)
    is rejected (401): forging the identity needs a key whose hash collides the owner's
    userId, which they do not have.
    """
    owner = await _setup_owner(sdk, room="edge-impersonate")
    attacker = bootstrap_root_identity("edge-impersonate-atk")
    cap = mint_device_cap(attacker.device["edPriv"], attacker.device["edPub"], _sub(attacker), owner_scope())
    forged = copy.deepcopy(cap)
    forged["issUserId"] = owner.creds.user_id  # claim to BE the room owner
    cur = (await owner.client.pull(keyring_pull("edge-impersonate"))).hash
    evil, _cek = create_keyring(attacker.device["edPriv"], attacker.device["edPub"], [attacker.device["kemPub"]])
    with pytest.raises(StarfishHttpError) as exc:
        await sdk(forged, attacker.device["edPriv"]).push(keyring_push("edge-impersonate"), evil.to_dict(), cur)
    assert exc.value.status == 401


async def test_user_id_is_a_128_bit_truncated_hash_of_the_pubkey():
    """A userId is sha256(edPub)[:32] — 32 hex chars = 16 bytes = 128 bits.

    Identity binding (owner-binding, `{identity}` path scoping, `_bind_auth_identity`)
    rests on this derivation. Pins the width so a change is caught. The space was
    widened from 64 to 128 bits so impersonating a SPECIFIC identity now needs a
    second-preimage on a 128-bit truncated hash (~2^128 keypair generations) —
    cryptographically infeasible, matching the 128-bit cap nonce.
    """
    user = bootstrap_root_identity("edge-uid-width")
    derived = hashlib.sha256(bytes.fromhex(user.device["edPub"])).hexdigest()[:32]
    assert user.user_id == derived
    assert len(user.user_id) == 32  # hex chars → 128-bit identity space


# ══════════════════════════════════════════════════════════════════════════════
# ROUND R6 — the public collections (rendezvous + public-read profile)
#
# Two collections are deliberately open: `pairingrendezvous` (public read+write, so
# a credential-less device can fetch its bundle) and `profile` (public read so the
# UI shows everyone's pseudo). These pin that "public" is scoped: an open READ is
# not an open WRITE, the open slot still self-expires (TTL) and stays size-bounded.
# ══════════════════════════════════════════════════════════════════════════════
async def test_anonymous_can_read_and_write_the_public_rendezvous_slot(sdk):
    """`pairingrendezvous` is `public` read+write — no cap needed either way.

    A credential-less new device must be able to fetch its pairing bundle, so the slot
    accepts an anonymous write and an anonymous read. Pins the intended openness; the
    bundle's confidentiality rests on E2E-wrapped CEKs + the root pin, NOT on access
    control of this slot.
    """
    anon = sdk()  # no cap_provider
    rid = "00112233445566778899aabbccddeeff"
    await anon.push(f"/push/_pairing/{rid}", {"hello": "world"}, None)  # 200, no cap
    res = await anon.pull(f"/pull/_pairing/{rid}")
    assert res.data.get("hello") == "world"


async def test_profile_public_read_is_open_but_write_is_not(sdk):
    """Profile reads are public; writes are not — open READ ≠ open WRITE.

    Alice's root device writes her pseudo. An anonymous party (no cap) reads it back —
    public read powers the chat UI's name display, and unlike `entitlements` (self-only
    read) a profile is cross-user visible. But an anonymous WRITE to her profile is
    refused: writes need her root device's `device:root`, so the open read does not
    imply an open write.
    """
    alice = bootstrap_root_identity("edge-pubprof-alice")
    acap = mint_device_cap(alice.device["edPriv"], alice.device["edPub"], _sub(alice), account_scope(alice.user_id))
    await sdk(acap, alice.device["edPriv"]).push(f"/push/user/{alice.user_id}/profile", {"v": 1, "pseudo": "Alice"}, None)

    anon_read = await sdk().pull(f"/pull/user/{alice.user_id}/profile")  # public read, no cap
    assert anon_read.data.get("pseudo") == "Alice"

    with pytest.raises(StarfishHttpError) as exc:  # but writing is not public
        await sdk().push(f"/push/user/{alice.user_id}/profile", {"v": 1, "pseudo": "hacked"}, anon_read.hash)
    assert exc.value.status in (401, 403)


async def test_public_rendezvous_slot_self_expires_via_ttl(sdk):
    """The public rendezvous slot self-expires (`ttl_ms=300_000`).

    A pushed bundle is readable immediately, but once the stored document ages past
    the collection's TTL the server returns empty — so a stale/abandoned bundle does
    not linger readable in the open slot. We model the age by writing a doc whose
    stored timestamp is 10 min in the past and confirming the read comes back empty.
    """
    rid = "ttlexpiretestid001122334455"
    old_ts = int(time.time() * 1000) - 600_000  # 10 min ago > the 5-min TTL
    await server.store.put(
        f"_pairing/{rid}",
        json.dumps({"v": 1, "data": {"capCert": "stale"}, "timestamps": {"data": old_ts}, "hash": ""}),
    )
    res = await sdk().pull(f"/pull/_pairing/{rid}")
    assert res.data == {}  # expired → server returns empty data


async def test_public_rendezvous_write_respects_its_8kb_limit(sdk):
    """Even a `public` collection enforces its size ceiling.

    The rendezvous slot is anonymously writable, but a body over its 8 KB
    `max_body_bytes` is rejected 413 — public write does not mean unbounded write
    (so the open slot can't be used to dump large blobs into the store for free).
    """
    rid = "sizetestid00112233445566aa"
    with pytest.raises(StarfishHttpError) as exc:
        await sdk().push(f"/push/_pairing/{rid}", {"pad": "z" * 9_000}, None)  # > 8192 bytes
    assert exc.value.status == 413
