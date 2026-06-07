"""``starfish-keyring`` — multi-recipient encryption layer.

Public surface: keyring lifecycle (create/add/rotate), encryptor factory,
wrap/unwrap primitives, recipient management bound to a Starfish collection,
and the locked protocol constants.
"""

from starfish_keyring.keyring import (
    KEYRING_IV_BYTES,
    KEYRING_WRAP_INFO,
    KEYRING_WRAP_SALT,
    Keyring,
    KeyringEncryptor,
    KeyringEpoch,
    WrappedKeyEntry,
    add_recipient,
    create_keyring,
    create_keyring_encryptor,
    rotate_epoch,
    unwrap_from_entry,
    verify_entry_signature,
    wrap_for_recipient,
)
from starfish_keyring.recipients import (
    AdderKeys,
    ListedRecipient,
    RecipientRef,
    add_recipient as add_collection_recipient,
    current_epoch,
    keyring_path_for,
    list_recipients,
    remove_recipient,
)
from starfish_keyring.seal import (
    SealedBlob,
    seal,
    seal_to_self,
    unseal,
    unseal_from_self,
    unseal_to_str,
)
from starfish_keyring._crypto_helpers import hkdf_bytes

__all__ = [
    "hkdf_bytes",
    "SealedBlob",
    "seal",
    "seal_to_self",
    "unseal",
    "unseal_from_self",
    "unseal_to_str",
    "KEYRING_IV_BYTES",
    "KEYRING_WRAP_INFO",
    "KEYRING_WRAP_SALT",
    "Keyring",
    "KeyringEncryptor",
    "KeyringEpoch",
    "WrappedKeyEntry",
    "add_recipient",
    "create_keyring",
    "create_keyring_encryptor",
    "rotate_epoch",
    "unwrap_from_entry",
    "verify_entry_signature",
    "wrap_for_recipient",
    "AdderKeys",
    "ListedRecipient",
    "RecipientRef",
    "add_collection_recipient",
    "current_epoch",
    "keyring_path_for",
    "list_recipients",
    "remove_recipient",
]
