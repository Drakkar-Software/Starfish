"""Group encryption utilities for Starfish.

Enables multiple users to share a common encrypted collection without sharing
a passphrase. Each member holds their own credentials; a Group Encryption Key
(GEK) is distributed per-member using X25519 ECDH key agreement.

Typical flow:
  1. Each user calls ``derive_credentials(passphrase)`` — includes ``group_public_key``
     and ``group_private_key``.
  2. Admin calls ``create_group_keyring(...)`` to build a keyring document.
  3. Members call ``create_group_encryptor(keyring, my_identity, my_private_key)``
     to obtain an ``Encryptor``.
  4. Pass the ``Encryptor`` to ``SyncManager`` via the ``encryptor`` parameter.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from starfish_protocol.crypto import _derive_key, IV_BYTES
from starfish_sdk.crypto import Encryptor, create_encryptor

# ── Constants ─────────────────────────────────────────────────────────────────

_ALGO = "AES-GCM"
_GROUP_WRAP_SALT = "starfish-group-wrap"
_GROUP_WRAP_INFO = "starfish-group-wrap"
_GROUP_ECDH_DOMAIN = "starfish-group-ecdh"
_GROUP_DATA_INFO = "starfish-group"
_GEK_BYTES = 32

# ── Types ─────────────────────────────────────────────────────────────────────


@dataclass
class GroupKeyPair:
    """An X25519 key pair for group encryption. Hex-encoded for easy serialization."""

    private_key: str
    """Hex-encoded X25519 private key (32 bytes). Keep secret — never store on server."""

    public_key: str
    """Hex-encoded X25519 public key (32 bytes). Safe to publish."""


@dataclass
class EpochKeyring:
    """One epoch's wrapped keys: each member's GEK encrypted to their public key."""

    admin_public_key: str
    """The admin's hex-encoded X25519 public key (used for ECDH by members)."""

    wrapped_keys: dict[str, str] = field(default_factory=dict)
    """Map from member identity (userId) → base64(IV || AES-GCM(GEK))."""


@dataclass
class GroupKeyring:
    """The full keyring document stored in a Starfish collection."""

    current_epoch: int
    """The epoch number currently used for new encryptions."""

    epochs: dict[str, EpochKeyring] = field(default_factory=dict)
    """All epochs keyed by epoch number string."""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict suitable for pushing to Starfish."""
        return {
            "currentEpoch": self.current_epoch,
            "epochs": {
                epoch: {
                    "adminPublicKey": kr.admin_public_key,
                    "wrappedKeys": kr.wrapped_keys,
                }
                for epoch, kr in self.epochs.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GroupKeyring":
        """Deserialize from a plain dict pulled from Starfish."""
        epochs = {}
        for epoch_str, epoch_data in data.get("epochs", {}).items():
            epochs[epoch_str] = EpochKeyring(
                admin_public_key=epoch_data["adminPublicKey"],
                wrapped_keys=epoch_data.get("wrappedKeys", {}),
            )
        return cls(current_epoch=data["currentEpoch"], epochs=epochs)


# ── Key derivation ─────────────────────────────────────────────────────────────


def derive_group_key_pair(passphrase: str, user_id: str) -> GroupKeyPair:
    """Derive a deterministic X25519 key pair from a passphrase + userId.

    The derivation uses SHA-256 with a fixed domain separator so it is distinct
    from the auth token and encryption key derivations. Same passphrase + userId
    always produces the same key pair on any device (stateless).
    """
    domain_input = f"{passphrase}:{user_id}:{_GROUP_ECDH_DOMAIN}".encode("utf-8")
    private_bytes = hashlib.sha256(domain_input).digest()  # 32 bytes
    private_key = X25519PrivateKey.from_private_bytes(private_bytes)
    public_key = private_key.public_key()

    priv_hex = private_bytes.hex()
    pub_hex = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return GroupKeyPair(private_key=priv_hex, public_key=pub_hex)


# ── GEK generation ─────────────────────────────────────────────────────────────


def generate_group_key() -> str:
    """Generate a random 256-bit Group Encryption Key as a hex string."""
    return os.urandom(_GEK_BYTES).hex()


# ── Key wrapping / unwrapping ──────────────────────────────────────────────────


def _ecdh_shared_secret(private_key_hex: str, public_key_hex: str) -> bytes:
    """Perform X25519 ECDH and return the 32-byte shared secret."""
    private_key = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    public_key = X25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    return private_key.exchange(public_key)


def wrap_group_key(gek: str, member_public_key: str, wrapper_private_key: str) -> str:
    """Wrap a GEK for a specific member using ECDH key agreement.

    The wrapper (admin) and member each have an X25519 key pair. ECDH between
    ``wrapper_private_key`` and ``member_public_key`` produces a shared secret,
    which is used to derive an AES-256-GCM key that encrypts the GEK.

    Returns base64(IV || AES-GCM-ciphertext).
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    shared_secret = _ecdh_shared_secret(wrapper_private_key, member_public_key)
    wrapping_key = _derive_key(shared_secret.hex(), _GROUP_WRAP_SALT, _GROUP_WRAP_INFO.encode())

    iv = os.urandom(IV_BYTES)
    aesgcm = AESGCM(wrapping_key)
    ciphertext = aesgcm.encrypt(iv, bytes.fromhex(gek), None)
    combined = iv + ciphertext
    return base64.b64encode(combined).decode("ascii")


def unwrap_group_key(wrapped: str, member_private_key: str, admin_public_key: str) -> str:
    """Unwrap a GEK using the member's private key and the admin's public key.

    ECDH between ``member_private_key`` and ``admin_public_key`` yields the same
    shared secret as the wrapping step, so the same AES key is derived and the
    GEK is recovered.

    Returns the GEK as a hex string.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag

    shared_secret = _ecdh_shared_secret(member_private_key, admin_public_key)
    wrapping_key = _derive_key(shared_secret.hex(), _GROUP_WRAP_SALT, _GROUP_WRAP_INFO.encode())

    combined = base64.b64decode(wrapped)
    iv = combined[:IV_BYTES]
    ciphertext = combined[IV_BYTES:]
    aesgcm = AESGCM(wrapping_key)
    try:
        gek_bytes = aesgcm.decrypt(iv, ciphertext, None)
    except InvalidTag as exc:
        raise ValueError("Failed to unwrap group key: invalid tag") from exc
    return gek_bytes.hex()


# ── Keyring management ─────────────────────────────────────────────────────────


def create_group_keyring(
    admin_key_pair: GroupKeyPair,
    members: dict[str, str],
    gek: str | None = None,
) -> tuple[GroupKeyring, str]:
    """Create a new group keyring document with epoch 1.

    Args:
        admin_key_pair: The admin's key pair.
        members: Map from member identity (userId) → hex public key.
        gek: Optional GEK to use; generated randomly if omitted.

    Returns:
        A tuple of (keyring, gek). The admin keeps the raw GEK to add future members.
    """
    resolved_gek = gek or generate_group_key()
    wrapped_keys: dict[str, str] = {}
    for member_id, member_public_key in members.items():
        wrapped_keys[member_id] = wrap_group_key(resolved_gek, member_public_key, admin_key_pair.private_key)
    keyring = GroupKeyring(
        current_epoch=1,
        epochs={
            "1": EpochKeyring(admin_public_key=admin_key_pair.public_key, wrapped_keys=wrapped_keys)
        },
    )
    return keyring, resolved_gek


def add_group_member(
    keyring: GroupKeyring,
    admin_key_pair: GroupKeyPair,
    current_gek: str,
    new_member_id: str,
    new_member_public_key: str,
) -> GroupKeyring:
    """Add a new member to the current epoch of an existing keyring.

    The admin supplies the current GEK (returned by ``create_group_keyring`` or
    ``rotate_group_key``) and their key pair to wrap it for the new member.
    Only the admin (whose public key matches the epoch's adminPublicKey) can add
    members, because all wrapped entries must use the same ECDH key pair.

    The new member can read all existing documents from the current epoch onward.
    """
    epoch_key = str(keyring.current_epoch)
    epoch_keyring = keyring.epochs.get(epoch_key)
    if not epoch_keyring:
        raise ValueError(f"Epoch {keyring.current_epoch} not found in keyring")
    if epoch_keyring.admin_public_key != admin_key_pair.public_key:
        raise ValueError(
            f"Provided key pair does not match the admin public key stored in epoch {keyring.current_epoch}"
        )

    wrapped = wrap_group_key(current_gek, new_member_public_key, admin_key_pair.private_key)

    new_wrapped_keys = {**epoch_keyring.wrapped_keys, new_member_id: wrapped}
    new_epochs = {
        **keyring.epochs,
        epoch_key: EpochKeyring(
            admin_public_key=epoch_keyring.admin_public_key,
            wrapped_keys=new_wrapped_keys,
        ),
    }
    return GroupKeyring(current_epoch=keyring.current_epoch, epochs=new_epochs)


def rotate_group_key(
    keyring: GroupKeyring,
    admin_key_pair: GroupKeyPair,
    remaining_members: dict[str, str],
    new_gek: str | None = None,
) -> tuple[GroupKeyring, str]:
    """Rotate the group key, creating a new epoch.

    Used when removing a member. The removed member retains their old epoch key
    (and can still read old documents), but cannot read new documents.

    Args:
        remaining_members: Map from identity → hex public key for members who keep access.

    Returns:
        A tuple of (updated_keyring, new_gek).
    """
    epoch_key = str(keyring.current_epoch)
    epoch_keyring = keyring.epochs.get(epoch_key)
    if epoch_keyring and epoch_keyring.admin_public_key != admin_key_pair.public_key:
        raise ValueError(
            f"Provided key pair does not match the admin public key stored in epoch {keyring.current_epoch}"
        )
    resolved_gek = new_gek or generate_group_key()
    new_epoch = keyring.current_epoch + 1
    wrapped_keys: dict[str, str] = {}
    for member_id, member_public_key in remaining_members.items():
        wrapped_keys[member_id] = wrap_group_key(resolved_gek, member_public_key, admin_key_pair.private_key)
    new_epoch_keyring = EpochKeyring(
        admin_public_key=admin_key_pair.public_key, wrapped_keys=wrapped_keys
    )
    new_keyring = GroupKeyring(
        current_epoch=new_epoch,
        epochs={**keyring.epochs, str(new_epoch): new_epoch_keyring},
    )
    return new_keyring, resolved_gek


# ── Encryptor factory ──────────────────────────────────────────────────────────


def create_group_encryptor(
    keyring: GroupKeyring,
    my_identity: str,
    my_private_key: str,
) -> Encryptor:
    """Create an Encryptor that decrypts any epoch and encrypts with the current epoch.

    Wire format: ``{ "_encrypted": "base64(IV || ciphertext)", "_epoch": N }``

    Args:
        keyring: The ``GroupKeyring`` fetched from Starfish (use ``GroupKeyring.from_dict``).
        my_identity: The caller's userId.
        my_private_key: The caller's hex-encoded X25519 private key.
    """
    # Unwrap GEK for each epoch we have a key for
    epoch_encryptors: dict[int, Encryptor] = {}
    for epoch_str, epoch_keyring in keyring.epochs.items():
        epoch = int(epoch_str)
        wrapped = epoch_keyring.wrapped_keys.get(my_identity)
        if wrapped is None:
            continue
        gek = unwrap_group_key(wrapped, my_private_key, epoch_keyring.admin_public_key)
        epoch_encryptors[epoch] = create_encryptor(gek, f"epoch-{epoch}", _GROUP_DATA_INFO)

    current_epoch = keyring.current_epoch
    if current_epoch not in epoch_encryptors:
        raise ValueError(
            f"No wrapped key found for identity {my_identity!r} in epoch {current_epoch}. "
            "Ensure the admin has added this member to the keyring."
        )

    current_encryptor = epoch_encryptors[current_epoch]

    class _GroupEncryptor:
        """Multi-epoch Encryptor for group-encrypted Starfish collections."""

        def encrypt(self, data: dict[str, Any]) -> dict[str, Any]:
            encrypted = current_encryptor.encrypt(data)
            return {**encrypted, "_epoch": current_epoch}

        def decrypt(self, wrapper: dict[str, Any]) -> dict[str, Any]:
            epoch = wrapper.get("_epoch")
            if not isinstance(epoch, int):
                epoch = current_epoch
            enc = epoch_encryptors.get(epoch)
            if enc is None:
                raise ValueError(
                    f"No key available for epoch {epoch}. "
                    "This document was encrypted in a different epoch. "
                    "Ensure your keyring is up to date."
                )
            return enc.decrypt(wrapper)

    return _GroupEncryptor()  # type: ignore[return-value]
