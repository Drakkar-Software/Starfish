"""Pairing-rendezvous helpers — behavioral tests (Python mirror of the TS suite).

Exercises the phone → computer return leg over a fake in-memory async client:
  - rendezvous_path_for derives a deterministic, path-safe slot from the qr_nonce
  - push → fetch → install round-trip
  - one-shot: clear_pairing_bundle empties the slot, a later fetch returns None
  - an empty / never-written slot fetches as None
"""

from __future__ import annotations

import base64

from starfish_identities.identity import derive_root_identity
from starfish_identities.cap_mint import scopes
from starfish_identities.pairing import (
    AssemblePairingBundleOpts,
    assemble_pairing_bundle,
    build_pairing_qr,
    generate_device_keys,
    install_pairing_bundle,
    parse_pairing_qr,
)
from starfish_identities.rendezvous import (
    RENDEZVOUS_PREFIX,
    clear_pairing_bundle,
    fetch_pairing_bundle,
    push_pairing_bundle,
    rendezvous_path_for,
)


class _FakeResult:
    def __init__(self, data: dict, hash: str) -> None:
        self.data = data
        self.hash = hash


class _FakeClient:
    """Minimal async stand-in for StarfishClient.

    The rendezvous helpers only call ``.pull`` / ``.push``; a missing slot pulls
    as ``{}`` / ``""`` (this server's behavior), and pushes are last-write-wins.
    """

    def __init__(self) -> None:
        self.store: dict[str, tuple[dict, str]] = {}
        self._counter = 0

    async def pull(self, path: str) -> _FakeResult:
        key = path[len("/pull/"):]
        entry = self.store.get(key)
        if entry is None:
            return _FakeResult({}, "")
        return _FakeResult(entry[0], entry[1])

    async def push(self, path: str, data: dict, base_hash: str | None) -> dict:
        key = path[len("/push/"):]
        self._counter += 1
        h = f"h{self._counter}"
        self.store[key] = (data, h)
        return {"hash": h}


def test_rendezvous_path_for_is_deterministic_hex() -> None:
    nonce_b64 = base64.b64encode(b"\xab" * 16).decode("ascii")
    path = rendezvous_path_for(nonce_b64)
    assert path == f"{RENDEZVOUS_PREFIX}/" + "ab" * 16
    assert rendezvous_path_for(nonce_b64) == path
    slot_id = path[len(RENDEZVOUS_PREFIX) + 1:]
    assert all(c in "0123456789abcdef" for c in slot_id)


async def test_rendezvous_roundtrip_push_fetch_install_clear() -> None:
    root = derive_root_identity("alice-root-passphrase")
    device = generate_device_keys()
    qr = build_pairing_qr(device["edPub"], device["kemPub"], scopes.root_all())
    parsed = parse_pairing_qr(qr)
    bundle = assemble_pairing_bundle(
        {"edPriv": root.keys.ed_priv, "edPub": root.keys.ed_pub},
        parsed,
        {},
        AssemblePairingBundleOpts(granted_scope=parsed.requested_scope),
    )

    client = _FakeClient()
    # New device side: nothing there yet.
    assert await fetch_pairing_bundle(client, parsed.qr_nonce) is None

    # Root side: publish the bundle.
    await push_pairing_bundle(client, parsed.qr_nonce, bundle)

    # New device side: a single fetch retrieves + installs (pinning the session
    # nonce and the known root identity).
    fetched = await fetch_pairing_bundle(client, parsed.qr_nonce)
    assert fetched is not None
    installed = install_pairing_bundle(
        fetched,
        device,
        now=bundle.cap_cert["nbf"] + 5,
        expected_qr_nonce=parsed.qr_nonce,
        expected_root_ed_pub=root.keys.ed_pub,
    )
    assert installed.credentials.device["edPub"] == device["edPub"]
    assert installed.credentials.root_ed_pub == root.keys.ed_pub

    # One-shot: clearing empties the slot; a later fetch returns None.
    await clear_pairing_bundle(client, parsed.qr_nonce)
    assert await fetch_pairing_bundle(client, parsed.qr_nonce) is None


async def test_fetch_empty_slot_returns_none() -> None:
    client = _FakeClient()
    nonce_b64 = base64.b64encode(b"\x01" * 16).decode("ascii")
    assert await fetch_pairing_bundle(client, nonce_b64) is None
