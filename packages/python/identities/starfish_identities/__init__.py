"""``starfish-identities`` — root + device identity extension.

Public surface: passphrase-derived root identities, device cap-cert
minting, the ``scopes.root_all`` preset, all pairing flows (QR +
server-relay), the per-user device directory, and the server plugin.
"""

from starfish_identities.identity import (
    BootstrapOrigin,
    RootIdentity,
    RootKeyPair,
    SECP256K1_BOOTSTRAP_CHALLENGE,
    derive_root_identity,
    derive_root_identity_from_secp256k1_signature,
)
from starfish_identities.cap_mint import (
    MintOpts,
    ScopePreset,
    mint_device_cap,
    scopes,
)
from starfish_identities.pairing import (
    AssemblePairingBundleOpts,
    DeviceCredentials,
    InstalledPairingResult,
    PairingBundle,
    PairingQrPayload,
    PairingRequestEncrypted,
    PairingResponseEncrypted,
    ProvisionDeviceOpts,
    ProvisionedDevice,
    RecoveredCek,
    WrappedCekEntry,
    assemble_pairing_bundle,
    bootstrap_root_identity,
    build_pairing_qr,
    build_pairing_request,
    build_pairing_response,
    derive_code_key,
    generate_device_keys,
    install_pairing_bundle,
    install_provisioned_device,
    parse_pairing_qr,
    provision_device,
    read_pairing_request,
    read_pairing_response,
)
from starfish_identities.rendezvous import (
    RENDEZVOUS_PREFIX,
    clear_pairing_bundle,
    fetch_pairing_bundle,
    push_pairing_bundle,
    rendezvous_path_for,
)
from starfish_identities.seal import (
    is_sealed_envelope,
    open_with_passphrase,
    seal_with_passphrase,
)
from starfish_identities.directory import (
    Directory,
    DirectoryEntry,
    ListDirectoryOpts,
    add_device_entry,
    devices_path_for,
    list_devices,
    remove_device_entry,
)
# Re-exported from the protocol layer: distinguishes a self-signed root-device
# cap from delegated devices/members (used by server-side root-only collections).
from starfish_protocol import is_root_device_cap


def __getattr__(name: str):
    """Lazy import of ``identities_server_plugin`` so apps that only use the
    client-side helpers don't pay the ``starfish_server`` import cost.
    """
    if name == "identities_server_plugin":
        from starfish_identities.plugin import identities_server_plugin as _p
        return _p
    raise AttributeError(f"module 'starfish_identities' has no attribute {name!r}")

__all__ = [
    "BootstrapOrigin",
    "RootIdentity",
    "RootKeyPair",
    "SECP256K1_BOOTSTRAP_CHALLENGE",
    "derive_root_identity",
    "derive_root_identity_from_secp256k1_signature",
    "MintOpts",
    "ScopePreset",
    "mint_device_cap",
    "scopes",
    "AssemblePairingBundleOpts",
    "DeviceCredentials",
    "InstalledPairingResult",
    "PairingBundle",
    "PairingQrPayload",
    "PairingRequestEncrypted",
    "PairingResponseEncrypted",
    "ProvisionDeviceOpts",
    "ProvisionedDevice",
    "RecoveredCek",
    "WrappedCekEntry",
    "assemble_pairing_bundle",
    "bootstrap_root_identity",
    "build_pairing_qr",
    "build_pairing_request",
    "build_pairing_response",
    "derive_code_key",
    "generate_device_keys",
    "install_pairing_bundle",
    "install_provisioned_device",
    "parse_pairing_qr",
    "provision_device",
    "read_pairing_request",
    "read_pairing_response",
    "RENDEZVOUS_PREFIX",
    "rendezvous_path_for",
    "push_pairing_bundle",
    "fetch_pairing_bundle",
    "clear_pairing_bundle",
    "seal_with_passphrase",
    "open_with_passphrase",
    "is_sealed_envelope",
    "Directory",
    "DirectoryEntry",
    "ListDirectoryOpts",
    "add_device_entry",
    "devices_path_for",
    "list_devices",
    "remove_device_entry",
    "identities_server_plugin",
    "is_root_device_cap",
]
