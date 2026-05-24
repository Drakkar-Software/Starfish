"""v3.0 pairing helpers (Python mirror of the TS ``pairing`` module).

Three flows are supported:

1. ``bootstrap_root_identity(passphrase)`` — first device of a user. Derives
   the root identity from the passphrase and mints a self-signed full-scope
   device cap-cert. The "device" IS the root keypair in this case.

2. QR pairing — the new device shows a QR encoding its keypair + requested
   scope; the root device assembles a :class:`PairingBundle` (cap-cert +
   per-collection wrapped CEKs); the new device installs it.

3. Server-relay pairing — same end-to-end intent as QR, but the QR is
   replaced by an encrypted blob sent through a relay. The encryption key
   is derived from a short 6-digit code via PBKDF2-HMAC-SHA256.

The wrap primitive used inside the bundle is the same HPKE-DHKEM-style
construction as :mod:`starfish_sdk.keyring`, but the on-the-wire shape is
stripped to ``{epoch, ephKem, ct}`` — the bundle does not carry the audit
signature because the surrounding cap-cert already authenticates the root.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Optional, TypedDict

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from starfish_protocol.cap import recipient_kem, verify_cap_cert
from starfish_protocol.hash import stable_stringify

from starfish_keyring import hkdf_bytes
from .cap_mint import MintOpts, mint_device_cap, scopes
from .identity import derive_root_identity

# ── Constants (locked) ────────────────────────────────────────────────────────

_CODE_KEY_SALT_PREFIX = b"starfish-pair"
# PBKDF2 iteration count for the relay code-key. Raised to OWASP's 2023
# SHA-256 floor (600 000). NOTE: no KDF cost rescues a ~20-bit 6-digit code
# from offline brute force once the relay ciphertext is captured — the relay
# MUST one-shot + rate-limit the code; prefer a longer code or a PAKE for
# high-threat deployments. See ``build_pairing_request`` and the docs.
_DEFAULT_PBKDF2_ITERATIONS = 600_000
_WRAP_SALT = b"starfish-wrap"
_WRAP_INFO = b"starfish-wrap"
_WRAP_IV_BYTES = 12


# ── Types ─────────────────────────────────────────────────────────────────────


@dataclass
class DeviceCredentials:
    """Credentials produced by bootstrap or pairing-install."""

    root_ed_pub: str
    """Hex — the user's root Ed25519 public key."""

    user_id: str
    """Hex 32 — ``sha256(root_ed_pub)[0:32]``."""

    device: dict[str, str]
    """``{"edPriv", "edPub", "kemPriv", "kemPub"}`` hex strings."""

    cap_cert: dict[str, Any]
    """Signed cap-cert (matches the TS ``CapCert`` shape)."""


@dataclass
class PairingQrPayload:
    """Decoded pairing-QR payload."""

    v: int
    dev_ed_pub: str
    dev_kem_pub: str
    requested_scope: dict[str, Any]
    qr_nonce: str
    """Standard base64 (padded) of the 16-byte nonce bytes."""
    alg: Optional[str] = None
    """The new device's identity suite. Absent (``None``) ⇒ ``ed25519`` — the only
    suite pairing supports today (the CEK wrap is X25519-only). A present,
    non-``ed25519`` value is rejected by :func:`assemble_pairing_bundle` until
    secp256k1 root pairing ships. Omitted on the wire for an ``ed25519`` device so
    existing QR encodings stay byte-identical."""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "v": self.v,
            "devEdPub": self.dev_ed_pub,
            "devKemPub": self.dev_kem_pub,
            "requestedScope": self.requested_scope,
            "qrNonce": self.qr_nonce,
        }
        # Emit only for a non-ed25519 device, so an ed25519 QR stays byte-identical.
        if self.alg is not None and self.alg != "ed25519":
            out["alg"] = self.alg
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PairingQrPayload":
        return cls(
            v=int(data["v"]),
            dev_ed_pub=data["devEdPub"],
            dev_kem_pub=data["devKemPub"],
            requested_scope=dict(data["requestedScope"]),
            qr_nonce=data["qrNonce"],
            alg=data.get("alg"),
        )


@dataclass
class WrappedCekEntry:
    """A single per-collection wrapped CEK inside a :class:`PairingBundle`."""

    epoch: int
    eph_kem: str
    ct: str

    def to_dict(self) -> dict[str, Any]:
        return {"epoch": self.epoch, "ephKem": self.eph_kem, "ct": self.ct}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WrappedCekEntry":
        return cls(epoch=int(data["epoch"]), eph_kem=data["ephKem"], ct=data["ct"])


@dataclass
class PairingBundle:
    """Cap-cert + wrapped CEKs sent root → new-device during pairing."""

    cap_cert: dict[str, Any]
    root_ed_pub: str
    wrapped_ceks: dict[str, WrappedCekEntry] = field(default_factory=dict)
    v: int = 1
    qr_nonce: Optional[str] = None
    """The ``qrNonce`` from the pairing QR this bundle answers, echoed back so
    the new device can bind the bundle to the exact pairing session it started.
    ``assemble_pairing_bundle`` always populates it; older bundles may omit it,
    so ``install_pairing_bundle`` only enforces it when the caller passes the
    nonce it generated."""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "v": self.v,
            "capCert": self.cap_cert,
            "rootEdPub": self.root_ed_pub,
            "wrappedCEKs": {k: e.to_dict() for k, e in self.wrapped_ceks.items()},
        }
        if self.qr_nonce is not None:
            out["qrNonce"] = self.qr_nonce
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PairingBundle":
        return cls(
            v=int(data.get("v", 1)),
            cap_cert=dict(data["capCert"]),
            root_ed_pub=data["rootEdPub"],
            wrapped_ceks={
                k: WrappedCekEntry.from_dict(v) for k, v in data.get("wrappedCEKs", {}).items()
            },
            qr_nonce=data.get("qrNonce"),
        )


@dataclass
class RecoveredCek:
    """A CEK recovered by :func:`install_pairing_bundle`."""

    epoch: int
    cek: bytes


@dataclass
class InstalledPairingResult:
    """Returned by :func:`install_pairing_bundle`."""

    credentials: DeviceCredentials
    ceks: dict[str, RecoveredCek]


class _CollectionCek(TypedDict):
    epoch: int
    cek: bytes


@dataclass
class AssemblePairingBundleOpts:
    """Optional knobs for :func:`assemble_pairing_bundle` (test reproducibility)."""

    granted_scope: Optional[dict[str, Any]] = None
    """Scope to actually grant the new device, overriding the peer-supplied
    ``parsed.requested_scope``. ``requested_scope`` arrives from the QR (or
    relay) and is attacker-influenceable: a tampered QR could request root-all
    access and — because a ``device`` cap binds the resolved identity to the
    issuer regardless of its paths — obtain a full root proxy. Pass
    ``granted_scope`` to bound what the paired device receives; the requested
    scope is then ignored."""

    adder_ed_pub_hex: Optional[str] = None
    nbf: Optional[int] = None
    ttl_sec: Optional[int] = None
    cert_nonce: Optional[bytes] = None
    eph_priv_by_collection: Optional[dict[str, bytes]] = None
    iv_by_collection: Optional[dict[str, bytes]] = None


@dataclass
class PairingRequestEncrypted:
    request_nonce: str
    iv: str
    ct: str
    v: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"v": self.v, "requestNonce": self.request_nonce, "iv": self.iv, "ct": self.ct}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PairingRequestEncrypted":
        return cls(
            v=int(data.get("v", 1)),
            request_nonce=data["requestNonce"],
            iv=data["iv"],
            ct=data["ct"],
        )


@dataclass
class PairingResponseEncrypted:
    request_nonce: str
    iv: str
    ct: str
    v: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"v": self.v, "requestNonce": self.request_nonce, "iv": self.iv, "ct": self.ct}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PairingResponseEncrypted":
        return cls(
            v=int(data.get("v", 1)),
            request_nonce=data["requestNonce"],
            iv=data["iv"],
            ct=data["ct"],
        )


# ── Wrap / unwrap primitive (bare CEK, no audit fields) ───────────────────────


def _x25519_public_bytes(priv: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )


def _x25519_shared(priv: bytes, pub: bytes) -> bytes:
    shared = X25519PrivateKey.from_private_bytes(priv).exchange(
        X25519PublicKey.from_public_bytes(pub)
    )
    # Reject the all-zero shared secret from a low-order point (RFC 7748 §6.1).
    # The keyring layer applies the same guard; pairing's ECDH must not be the
    # weaker path. The GCM tag would also catch the resulting wrong key, but this
    # fails closed earlier and keeps the two layers aligned.
    if not any(shared):
        raise ValueError("Rejected zero X25519 shared secret (small-subgroup attack)")
    return shared


def _assert_ed25519_pairing_suite(alg: Optional[str], what: str) -> None:
    """Guard the deferred secp256k1 pairing path. The pairing CEK wrap
    (:func:`_wrap_cek_bare`/:func:`_unwrap_cek_bare`) is X25519-only: a secp256k1
    x-only key fed into X25519 ECDH yields a wrong shared secret and would surface
    as an opaque GCM-tag failure at unwrap. Until secp256k1 root pairing ships,
    reject any non-``ed25519`` suite up front. ``None`` defaults to ``ed25519``
    (the absent-tag convention used across the protocol). Mirrors TS."""
    if alg is not None and alg != "ed25519":
        raise ValueError(
            f'secp256k1 root pairing not yet supported: {what} is "{alg}", but the '
            "pairing CEK wrap is X25519-only. Deferred to the bring-your-own-nsec phase."
        )


def _wrap_cek_bare(
    cek: bytes,
    recipient_kem_pub_hex: str,
    eph_priv: Optional[bytes] = None,
    iv: Optional[bytes] = None,
) -> tuple[str, str]:
    """Returns ``(eph_kem_hex, ct_b64)``. ``ct = b64(iv || aes-gcm)``."""
    recipient_kem_pub = bytes.fromhex(recipient_kem_pub_hex)
    eph = eph_priv if eph_priv is not None else secrets.token_bytes(32)
    eph_pub = _x25519_public_bytes(eph)
    shared = _x25519_shared(eph, recipient_kem_pub)
    wrap_key = hkdf_bytes(shared, _WRAP_SALT, _WRAP_INFO, 32)
    iv_bytes = iv if iv is not None else secrets.token_bytes(_WRAP_IV_BYTES)
    aead = AESGCM(wrap_key)
    ct = aead.encrypt(iv_bytes, cek, None)
    return eph_pub.hex(), base64.b64encode(iv_bytes + ct).decode("ascii")


def _unwrap_cek_bare(eph_kem_hex: str, ct_b64: str, recipient_kem_priv_hex: str) -> bytes:
    eph_pub = bytes.fromhex(eph_kem_hex)
    recipient_priv = bytes.fromhex(recipient_kem_priv_hex)
    shared = _x25519_shared(recipient_priv, eph_pub)
    wrap_key = hkdf_bytes(shared, _WRAP_SALT, _WRAP_INFO, 32)
    blob = base64.b64decode(ct_b64)
    if len(blob) < _WRAP_IV_BYTES:
        raise ValueError("Wrapped pairing CEK ciphertext shorter than IV length")
    iv = blob[:_WRAP_IV_BYTES]
    ct = blob[_WRAP_IV_BYTES:]
    aead = AESGCM(wrap_key)
    try:
        return aead.decrypt(iv, ct, None)
    except InvalidTag as exc:
        raise ValueError("Failed to unwrap pairing CEK: AES-GCM authentication failed") from exc


# ── base64url helpers ─────────────────────────────────────────────────────────


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(encoded: str) -> bytes:
    rem = len(encoded) % 4
    padded = encoded + ("=" * (4 - rem) if rem else "")
    return base64.urlsafe_b64decode(padded)


# ── Bootstrap ─────────────────────────────────────────────────────────────────


def bootstrap_root_identity(passphrase: str) -> DeviceCredentials:
    """Derive root identity from a passphrase and self-sign a full-scope device cap-cert."""
    root = derive_root_identity(passphrase)
    cap_cert = mint_device_cap(
        root.keys.ed_priv,
        root.keys.ed_pub,
        {"edPubHex": root.keys.ed_pub, "kemPubHex": root.keys.kem_pub},
        scopes.root_all(),
    )
    return DeviceCredentials(
        root_ed_pub=root.keys.ed_pub,
        user_id=root.user_id,
        device={
            "edPriv": root.keys.ed_priv,
            "edPub": root.keys.ed_pub,
            "kemPriv": root.keys.kem_priv,
            "kemPub": root.keys.kem_pub,
        },
        cap_cert=cap_cert,
    )


# ── QR encoding / parsing ─────────────────────────────────────────────────────


def build_pairing_qr(
    dev_ed_pub: str,
    dev_kem_pub: str,
    requested_scope: dict[str, Any],
    qr_nonce: Optional[bytes] = None,
    alg: Optional[str] = None,
) -> str:
    """Encode a pairing QR payload as ``base64url(stable_stringify(payload))``."""
    nonce_bytes = qr_nonce if qr_nonce is not None else secrets.token_bytes(16)
    payload: dict[str, Any] = {
        "v": 1,
        "devEdPub": dev_ed_pub,
        "devKemPub": dev_kem_pub,
        "requestedScope": requested_scope,
        "qrNonce": base64.b64encode(nonce_bytes).decode("ascii"),
    }
    # Emitted only for a non-ed25519 device, so an ed25519 QR stays byte-identical
    # (and assemble rejects it anyway until secp256k1 pairing ships).
    if alg is not None and alg != "ed25519":
        payload["alg"] = alg
    canonical = stable_stringify(payload).encode("utf-8")
    return _b64url_encode(canonical)


def parse_pairing_qr(payload: str) -> PairingQrPayload:
    """Decode a string produced by :func:`build_pairing_qr`."""
    raw = _b64url_decode(payload)
    obj = json.loads(raw.decode("utf-8"))
    if obj.get("v") != 1:
        raise ValueError(f"Unsupported pairing QR version: {obj.get('v')}")
    return PairingQrPayload.from_dict(obj)


# ── Bundle assembly (root side) ───────────────────────────────────────────────


def assemble_pairing_bundle(
    root_ed_key: dict[str, str],
    parsed: PairingQrPayload,
    current_epoch_by_collection: dict[str, _CollectionCek],
    opts: Optional[AssemblePairingBundleOpts] = None,
) -> PairingBundle:
    """Root-device side of a pairing exchange.

    Mints a device cap-cert and wraps each in-scope collection's current CEK for
    the new device's KEM pub.

    Fails closed: ``opts.granted_scope`` is REQUIRED. The peer-supplied
    ``parsed.requested_scope`` travels in the QR / relay payload and is therefore
    attacker-influenceable, and a ``device`` cap is a root proxy regardless of
    its paths — so defaulting the grant to the requested scope let a hostile QR
    mint a full-account proxy. The root must state the scope it grants explicitly.
    """
    if opts is None:
        opts = AssemblePairingBundleOpts()
    if opts.granted_scope is None:
        raise ValueError(
            "assemble_pairing_bundle: `granted_scope` is required — the QR/relay-supplied "
            "requested_scope is attacker-influenceable and a device cap is a root proxy "
            "regardless of its paths. Pass an explicit granted_scope to bound the delegated "
            "authority."
        )
    mint_opts = MintOpts(
        nbf=opts.nbf,
        ttl_sec=opts.ttl_sec,
        nonce=opts.cert_nonce,
    )
    scope_to_grant = opts.granted_scope
    # The new device's KEM key is wrapped over X25519 below; a secp256k1 device
    # would silently produce a garbage shared secret. Reject it loudly up front.
    _assert_ed25519_pairing_suite(parsed.alg, "the pairing device suite")
    cap_cert = mint_device_cap(
        root_ed_key["edPriv"],
        root_ed_key["edPub"],
        {"edPubHex": parsed.dev_ed_pub, "kemPubHex": parsed.dev_kem_pub},
        scope_to_grant,
        mint_opts,
    )

    wrapped: dict[str, WrappedCekEntry] = {}
    for collection, entry in current_epoch_by_collection.items():
        eph_priv = (opts.eph_priv_by_collection or {}).get(collection)
        iv = (opts.iv_by_collection or {}).get(collection)
        eph_kem, ct = _wrap_cek_bare(entry["cek"], parsed.dev_kem_pub, eph_priv, iv)
        wrapped[collection] = WrappedCekEntry(epoch=entry["epoch"], eph_kem=eph_kem, ct=ct)

    _ = opts.adder_ed_pub_hex  # reserved for future use; cap-cert iss is the source of truth
    return PairingBundle(
        v=1,
        cap_cert=cap_cert,
        root_ed_pub=root_ed_key["edPub"],
        wrapped_ceks=wrapped,
        qr_nonce=parsed.qr_nonce,
    )


# ── Bundle install (new-device side) ──────────────────────────────────────────


def install_pairing_bundle(
    bundle: PairingBundle,
    device: dict[str, str],
    *,
    now: Optional[int] = None,
    expected_qr_nonce: Optional[str] = None,
    expected_root_ed_pub: Optional[str] = None,
) -> InstalledPairingResult:
    """New-device side of the pairing exchange.

    Fully verifies the cap-cert (signature, not-before / expiry window, and
    well-formedness), confirms it is a ``device`` cap issued by the bundle's
    root for this device's keys, optionally binds it to the pairing session via
    the QR nonce, then unwraps each wrapped CEK. Raises :class:`ValueError` on
    any check failure or if an unwrap fails.

    :param now: Unix seconds for the cap-cert window check; defaults to the
        current time (override for deterministic tests).
    :param expected_qr_nonce: The ``qrNonce`` this device put in its own pairing
        QR. When supplied, the bundle's ``qr_nonce`` MUST match it, binding the
        bundle to this pairing session so a replayed/stale bundle is rejected.
    :param expected_root_ed_pub: The root Ed25519 pubkey (hex) this device
        expects to be paired to. When supplied, the bundle's ``root_ed_pub``
        MUST equal it, so a bundle minted by a *different* root is rejected.
        Without this pin the device trusts whatever root signed the bundle,
        which over an open rendezvous lets an attacker's own root provision this
        device into THEIR account. Pass it whenever the caller already knows the
        target account's root pubkey; otherwise surface the bundle's
        ``root_ed_pub`` fingerprint for the user to compare with the root device.
    """
    now_sec = now if now is not None else int(time.time())
    # The wrapped CEKs are unwrapped over X25519 below; reject a non-ed25519 cap
    # up front (issuer, subject, or recipient KEM) so a secp256k1 bundle fails
    # with a clear "not yet supported" rather than an opaque GCM-tag error.
    _assert_ed25519_pairing_suite(bundle.cap_cert.get("issAlg"), "the bundle cap-cert issuer suite")
    _assert_ed25519_pairing_suite(bundle.cap_cert.get("subAlg"), "the bundle cap-cert subject suite")
    _assert_ed25519_pairing_suite(recipient_kem(bundle.cap_cert)[1], "the bundle cap-cert KEM suite")
    # Full verification: signature + not-before/expiry window + well-formedness.
    # The previous signature-only check accepted expired or not-yet-valid certs.
    verify_result = verify_cap_cert(bundle.cap_cert, now=now_sec)
    if not verify_result.get("ok"):
        reason = verify_result.get("reason", "unknown")
        raise ValueError(f"Pairing bundle cap-cert is invalid: {reason}")
    # A pairing bundle delivers a device proxy. Rejecting any other kind stops a
    # signed ``member`` cap (which binds identity to its subject, not the issuer)
    # from being installed and treated as a root-proxy device credential.
    if bundle.cap_cert.get("kind") != "device":
        raise ValueError(
            f'Pairing bundle cap-cert must be kind="device", got "{bundle.cap_cert.get("kind")}"'
        )
    # The cap-cert must be issued by the root the bundle claims.
    if bundle.cap_cert["iss"] != bundle.root_ed_pub:
        raise ValueError("Pairing bundle cap-cert issuer does not match bundle.root_ed_pub")
    # Pin the expected root when the caller knows it: rejects a bundle minted by
    # a different root (e.g. an attacker's own root answering an open rendezvous
    # and trying to provision this device into their account).
    if expected_root_ed_pub is not None and bundle.root_ed_pub != expected_root_ed_pub:
        raise ValueError("Pairing bundle rootEdPub does not match the expected root identity")
    if (
        bundle.cap_cert["sub"] != device["edPub"]
        or bundle.cap_cert["subKem"] != device["kemPub"]
    ):
        raise ValueError("Pairing bundle cap-cert subject does not match this device")
    # Bind the bundle to the pairing session that produced the QR, when known.
    if expected_qr_nonce is not None and bundle.qr_nonce != expected_qr_nonce:
        raise ValueError("Pairing bundle qrNonce does not match the expected pairing session")

    ceks: dict[str, RecoveredCek] = {}
    for collection, entry in bundle.wrapped_ceks.items():
        cek = _unwrap_cek_bare(entry.eph_kem, entry.ct, device["kemPriv"])
        ceks[collection] = RecoveredCek(epoch=entry.epoch, cek=cek)

    credentials = DeviceCredentials(
        root_ed_pub=bundle.root_ed_pub,
        user_id=bundle.cap_cert["issUserId"],
        device=dict(device),
        cap_cert=bundle.cap_cert,
    )
    return InstalledPairingResult(credentials=credentials, ceks=ceks)


# ── One-way device provisioning (single blob, root → new device) ──────────────
#
# An alternative to the QR / relay exchanges: the root device plays BOTH roles.
# It generates the new device's keypair, mints its cap (with a caller-chosen
# scope + expiry), and assembles the bundle — all in one step. The new device
# only ever *receives* the result; it sends nothing back.
#
# SECURITY: the new device's PRIVATE keys are generated here, off-device, and
# travel inside ``ProvisionedDevice.device_keys``. Whoever reads that blob owns a
# full clone of the device (private keys + cap + any wrapped CEKs). Use one-way
# provisioning only over a channel you would trust with the collection keys
# themselves; prefer the two-way QR / relay flow when key exposure is a concern.


@dataclass
class ProvisionDeviceOpts:
    """Optional knobs for :func:`provision_device`."""

    scope: dict[str, Any]
    """Caps to grant the provisioned device. REQUIRED — provisioning never
    defaults to root scope. Use ``scopes.root_all()`` for a full account clone
    (the historic behavior), or a narrower preset to bound the new device."""

    current_epoch_by_collection: Optional[dict[str, _CollectionCek]] = None
    """Per-collection current CEKs to wrap into the bundle so the new device can
    read existing ciphertext immediately. Same shape ``assemble_pairing_bundle``
    takes as its third positional argument; here it is an option because
    ``provision_device`` is single-argument-shaped. Defaults to none."""

    ttl_sec: Optional[int] = None
    nbf: Optional[int] = None
    cert_nonce: Optional[bytes] = None
    device_keys: Optional[dict[str, str]] = None
    """Pre-generated device keys ``{"edPriv","edPub","kemPriv","kemPub"}``.
    Provide for deterministic tests; otherwise fresh keys are generated."""

    eph_priv_by_collection: Optional[dict[str, bytes]] = None
    iv_by_collection: Optional[dict[str, bytes]] = None


@dataclass
class ProvisionedDevice:
    """Result of :func:`provision_device`: the new device's keys + its bundle."""

    device_keys: dict[str, str]
    """The freshly generated device keypair. CONTAINS PRIVATE KEYS — see the
    security note above. Hand the whole object to the new device."""

    bundle: PairingBundle
    """The pairing bundle (device cap-cert + wrapped CEKs) for the new device."""

    def to_dict(self) -> dict[str, Any]:
        return {"deviceKeys": dict(self.device_keys), "bundle": self.bundle.to_dict()}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProvisionedDevice":
        return cls(
            device_keys=dict(data["deviceKeys"]),
            bundle=PairingBundle.from_dict(data["bundle"]),
        )


def generate_device_keys() -> dict[str, str]:
    """Generate a fresh Ed25519 (sign) + X25519 (KEM) device keypair (hex)."""
    ed_priv = Ed25519PrivateKey.generate()
    kem_priv = X25519PrivateKey.generate()
    return {
        "edPriv": ed_priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex(),
        "edPub": ed_priv.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex(),
        "kemPriv": kem_priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex(),
        "kemPub": kem_priv.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex(),
    }


def provision_device(
    root_ed_key: dict[str, str],
    opts: ProvisionDeviceOpts,
) -> ProvisionedDevice:
    """Root-device side of one-way provisioning.

    Generates the new device's keypair, mints a ``device`` cap-cert with the
    caller-chosen ``scope`` and expiry, and assembles a pairing bundle wrapping
    any ``current_epoch_by_collection`` CEKs to the new device's KEM pub. Returns
    the device keys + bundle as a single blob to hand off (e.g. a setup code).

    Unlike the QR / relay flows there is no peer-supplied scope to distrust: the
    scope is whatever the caller passes, bound via ``granted_scope``.
    """
    device_keys = opts.device_keys if opts.device_keys is not None else generate_device_keys()
    parsed = PairingQrPayload(
        v=1,
        dev_ed_pub=device_keys["edPub"],
        dev_kem_pub=device_keys["kemPub"],
        requested_scope=opts.scope,
        qr_nonce=base64.b64encode(secrets.token_bytes(16)).decode("ascii"),
    )
    bundle = assemble_pairing_bundle(
        root_ed_key,
        parsed,
        opts.current_epoch_by_collection or {},
        AssemblePairingBundleOpts(
            granted_scope=opts.scope,
            nbf=opts.nbf,
            ttl_sec=opts.ttl_sec,
            cert_nonce=opts.cert_nonce,
            eph_priv_by_collection=opts.eph_priv_by_collection,
            iv_by_collection=opts.iv_by_collection,
        ),
    )
    return ProvisionedDevice(device_keys=device_keys, bundle=bundle)


def install_provisioned_device(
    provisioned: ProvisionedDevice,
    *,
    now: Optional[int] = None,
    expected_qr_nonce: Optional[str] = None,
) -> InstalledPairingResult:
    """New-device side of one-way provisioning.

    Installs a :class:`ProvisionedDevice` blob: verifies the bundle's cap-cert
    and unwraps its CEKs exactly as :func:`install_pairing_bundle`, using the
    device keys carried in the blob.
    """
    return install_pairing_bundle(
        provisioned.bundle,
        provisioned.device_keys,
        now=now,
        expected_qr_nonce=expected_qr_nonce,
    )


# ── Server-relay pairing (code-derived encryption) ────────────────────────────


def derive_code_key(
    code: str,
    salt: bytes,
    iterations: int = _DEFAULT_PBKDF2_ITERATIONS,
) -> bytes:
    """Derive a 32-byte symmetric key from a code via PBKDF2-HMAC-SHA256.

    Salt is ``b"starfish-pair" + salt``.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_CODE_KEY_SALT_PREFIX + salt,
        iterations=iterations,
    )
    return kdf.derive(code.encode("utf-8"))


def _aesgcm_encrypt_with_code_key(
    code: str, request_nonce_bytes: bytes, plaintext: bytes
) -> tuple[str, str]:
    key = derive_code_key(code, request_nonce_bytes)
    aead = AESGCM(key)
    iv = secrets.token_bytes(_WRAP_IV_BYTES)
    ct = aead.encrypt(iv, plaintext, None)
    return base64.b64encode(iv).decode("ascii"), base64.b64encode(ct).decode("ascii")


def _aesgcm_decrypt_with_code_key(
    code: str, request_nonce_bytes: bytes, iv_b64: str, ct_b64: str
) -> bytes:
    key = derive_code_key(code, request_nonce_bytes)
    aead = AESGCM(key)
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ct_b64)
    try:
        return aead.decrypt(iv, ct, None)
    except InvalidTag as exc:
        raise ValueError(
            "Failed to decrypt relay payload (wrong code or tampered ciphertext)"
        ) from exc


def _pairing_request_pop_input(
    dev_ed_pub: str, dev_kem_pub: str, request_nonce_b64: str
) -> bytes:
    """Canonical signing input for the relay request's proof-of-possession.

    Binds the device's Ed25519 + KEM pubkeys to the request nonce so a relay
    cannot substitute a ``devKemPub`` (and harvest the wrapped CEKs) while
    keeping a ``devEdPub`` it does not control. ``request_nonce_b64`` is the
    standard-base64 request nonce exactly as it appears on the envelope.
    """
    return stable_stringify(
        {
            "devEdPub": dev_ed_pub,
            "devKemPub": dev_kem_pub,
            "requestNonce": request_nonce_b64,
        }
    ).encode("utf-8")


def build_pairing_request(
    device: dict[str, str],
    code: str,
    request_nonce: Optional[bytes] = None,
) -> PairingRequestEncrypted:
    """Build the encrypted pairing request the new device sends through a relay.

    Plaintext is ``stable_stringify({devEdPub, devKemPub, popSig})``, where
    ``popSig`` is an Ed25519 proof-of-possession over
    ``{devEdPub, devKemPub, requestNonce}`` signed with the device's ``edPriv``.
    The PoP binds the KEM pubkey to the Ed25519 pubkey under a key only the
    device holds, so a relay cannot swap ``devKemPub`` for one it controls
    without re-signing. ``device`` must therefore include ``edPriv``.

    Security: the code-derived AES key still rests on the secrecy and entropy of
    the short ``code``. The PoP does NOT stop an attacker who fully learns the
    code from substituting BOTH device keys; the relay MUST one-shot +
    rate-limit the code, and high-threat deployments should use a longer code or
    a PAKE.
    """
    nonce_bytes = request_nonce if request_nonce is not None else secrets.token_bytes(16)
    request_nonce_b64 = base64.b64encode(nonce_bytes).decode("ascii")
    signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(device["edPriv"]))
    pop_sig = base64.b64encode(
        signer.sign(
            _pairing_request_pop_input(device["edPub"], device["kemPub"], request_nonce_b64)
        )
    ).decode("ascii")
    payload = {
        "devEdPub": device["edPub"],
        "devKemPub": device["kemPub"],
        "popSig": pop_sig,
    }
    plaintext = stable_stringify(payload).encode("utf-8")
    iv_b64, ct_b64 = _aesgcm_encrypt_with_code_key(code, nonce_bytes, plaintext)
    return PairingRequestEncrypted(
        v=1,
        request_nonce=request_nonce_b64,
        iv=iv_b64,
        ct=ct_b64,
    )


def read_pairing_request(
    encrypted: PairingRequestEncrypted, code: str
) -> dict[str, str]:
    """Decrypt a relayed pairing request and verify its proof-of-possession.

    Raises ``ValueError`` if the payload is missing fields or if ``popSig``
    does not verify against ``devEdPub`` over ``{devEdPub, devKemPub,
    requestNonce}`` — i.e. the request was tampered with (e.g. a relay
    substituted ``devKemPub``).
    """
    nonce_bytes = base64.b64decode(encrypted.request_nonce)
    pt = _aesgcm_decrypt_with_code_key(code, nonce_bytes, encrypted.iv, encrypted.ct)
    parsed = json.loads(pt.decode("utf-8"))
    if (
        not isinstance(parsed, dict)
        or "devEdPub" not in parsed
        or "devKemPub" not in parsed
    ):
        raise ValueError("Relay request payload missing devEdPub/devKemPub")
    if "popSig" not in parsed or not isinstance(parsed["popSig"], str):
        raise ValueError(
            "Relay request payload missing proof-of-possession signature (popSig)"
        )
    try:
        verifier = Ed25519PublicKey.from_public_bytes(bytes.fromhex(parsed["devEdPub"]))
        verifier.verify(
            base64.b64decode(parsed["popSig"]),
            _pairing_request_pop_input(
                parsed["devEdPub"], parsed["devKemPub"], encrypted.request_nonce
            ),
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError(
            "Relay request proof-of-possession signature is invalid"
        ) from exc
    return {"devEdPub": parsed["devEdPub"], "devKemPub": parsed["devKemPub"]}


def build_pairing_response(
    bundle: PairingBundle,
    code: str,
    request_nonce: str,
) -> PairingResponseEncrypted:
    """Build the encrypted pairing response the root device sends through the relay."""
    nonce_bytes = base64.b64decode(request_nonce)
    plaintext = stable_stringify(bundle.to_dict()).encode("utf-8")
    iv_b64, ct_b64 = _aesgcm_encrypt_with_code_key(code, nonce_bytes, plaintext)
    return PairingResponseEncrypted(
        v=1,
        request_nonce=request_nonce,
        iv=iv_b64,
        ct=ct_b64,
    )


def read_pairing_response(
    encrypted: PairingResponseEncrypted, code: str
) -> PairingBundle:
    """Decrypt a relayed pairing response."""
    nonce_bytes = base64.b64decode(encrypted.request_nonce)
    pt = _aesgcm_decrypt_with_code_key(code, nonce_bytes, encrypted.iv, encrypted.ct)
    parsed = json.loads(pt.decode("utf-8"))
    return PairingBundle.from_dict(parsed)


__all__ = [
    "AssemblePairingBundleOpts",
    "DeviceCredentials",
    "InstalledPairingResult",
    "PairingBundle",
    "PairingQrPayload",
    "PairingRequestEncrypted",
    "PairingResponseEncrypted",
    "RecoveredCek",
    "WrappedCekEntry",
    "assemble_pairing_bundle",
    "bootstrap_root_identity",
    "build_pairing_qr",
    "build_pairing_request",
    "build_pairing_response",
    "derive_code_key",
    "install_pairing_bundle",
    "parse_pairing_qr",
    "read_pairing_request",
    "read_pairing_response",
]
