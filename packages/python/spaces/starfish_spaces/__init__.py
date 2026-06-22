"""starfish-spaces — space + node management for Starfish.

Public surface (mirrors ``@drakkar.software/starfish-spaces``):

- **Config & layout**: :func:`configure_spaces`, :func:`get_spaces_config`,
  :class:`SpaceLayout`, :data:`default_space_layout`, :func:`default_user_id_from_ed_pub`
- **Session**: :class:`Session`, :func:`build_session`, :func:`derive_session`
- **Registry**: :func:`create_space`, :func:`read_spaces`, :func:`build_space`, ...
- **Members**: :func:`invite_to_space`, :func:`accept_space_invite`,
  :func:`create_space_invite_link`, :func:`join_space_by_link`, ...
- **Nodes**: :func:`create_node`, :func:`invite_to_node`, :func:`accept_node_invite`, ...
- **Resource requests**: :func:`submit_resource_request`, :func:`scan_resource_requests`, ...
- **Identity link**: :class:`IdentityLink`, :func:`decode_identity_link`, ...
- **Server plugin**: :func:`create_spaces_role_enricher`,
  :func:`create_spaces_directory_server_plugin` (lazy-imported to avoid pulling
  in ``starfish_server`` for client-only users).
"""

from __future__ import annotations

# ── Config & layout ───────────────────────────────────────────────────────────
from starfish_spaces.config import (
    KvAdapter,
    NodeAccess,
    ObjectNode,
    ObjectsIndex,
    ObjectType,
    SealedBlob,
    Space,
    SpaceLayout,
    SpacesConfig,
    configure_spaces,
    get_spaces_config,
)
from starfish_spaces.layout import (
    OBJECT_COLLECTIONS,
    RECIPIENT_LABEL_LEN,
    USER_ID_HEX_LENGTH,
    default_space_layout,
    default_user_id_from_ed_pub,
)

# ── Session ────────────────────────────────────────────────────────────────────
from starfish_spaces.session import (
    BuildLinkedSessionOpts,
    BuildSessionOpts,
    LinkedIdentity,
    Session,
    build_linked_session,
    build_session,
    derive_session,
    fingerprint_from_user_id,
    generate_seed_words,
    is_valid_seed,
    owner_trusted_adders,
)

# ── Client helpers ─────────────────────────────────────────────────────────────
from starfish_spaces.client import (
    ClientOpts,
    DeviceKeys,
    PublicProfile,
    add_keyring_recipient_core,
    add_space_keyring_recipient,
    build_auth_headers,
    build_encryptor,
    cap_provider_for,
    ensure_profile_keys,
    ensure_pseudo,
    ensure_space_keyring_recipient,
    is_already_present_recipient,
    is_keyring_missing,
    make_anon_space_client,
    make_space_client,
    open_encryptor,
    owner_ensure_keyring,
    owner_ensure_space_keyring,
    read_profile,
    read_profiles,
    write_profile,
)

# ── Keyed store ────────────────────────────────────────────────────────────────
from starfish_spaces.keyed_store import (
    ComposedStore,
    KeyedStore,
    create_composed_store,
    create_keyed_store,
)

# ── Space access error ─────────────────────────────────────────────────────────
from starfish_spaces.space_access_error import SpaceAccessError

# ── Space access store ─────────────────────────────────────────────────────────
from starfish_spaces.space_access_store import (
    SpaceAccessEntry,
    clear_persisted_space_access,
    clear_space_access_store,
    configure_space_access_store,
    get_node_access_entry,
    get_node_keyring_access_entry,
    get_node_stream_access_entry,
    get_space_access_entry,
    hydrate_space_access_store,
    link_access_from_store,
    local_space_access_entries,
    member_caps_from_store,
    remove_node_access_entry,
    remove_node_keyring_access_entry,
    remove_node_stream_access_entry,
    remove_space_access_entry,
    save_node_access_entry,
    save_node_keyring_access_entry,
    save_node_stream_access_entry,
    save_space_access_entry,
)

# ── Account seal ──────────────────────────────────────────────────────────────
from starfish_spaces.account_seal import (
    seal_to_recipient,
    seal_to_self,
    unseal_from_recipient,
    unseal_from_self,
)

# ── Request verify ─────────────────────────────────────────────────────────────
from starfish_spaces.request_verify import sign_kem_sig, verify_kem_sig

# ── CAS retry ─────────────────────────────────────────────────────────────────
from starfish_spaces.cas_retry import run_cas

# ── Objects (pure tree algorithms) ────────────────────────────────────────────
from starfish_spaces.objects import add_object, build_tree

# ── Node keyring ──────────────────────────────────────────────────────────────
from starfish_spaces.node_keyring import (
    NodeKeyringRecipient,
    add_node_keyring_recipient,
    build_node_encryptor,
    ensure_node_keyring_recipient,
    open_node_encryptor,
    owner_ensure_node_keyring,
    remove_node_keyring_recipient,
)

# ── Space access resolver ──────────────────────────────────────────────────────
from starfish_spaces.space_access import (
    NodeAccessHandle,
    build_node_access,
    clear_node_access_cache,
    get_node_access,
    get_node_stream_client,
    get_space_client,
)

# ── Token types ────────────────────────────────────────────────────────────────
from starfish_spaces.token_types import (
    JoinRequest,
    NodeInviteBundle,
    NodeInviteKind,
    NodeInviteLinkToken,
    ResourceGrant,
    ResourceReject,
    ResourceRequest,
    SpaceInviteLinkToken,
    StoredNodeInvite,
)

# ── Invite helpers ─────────────────────────────────────────────────────────────
from starfish_spaces.invite_helpers import (
    CapSubject,
    adder_of,
    assert_cap_for_me,
    cap_nonce,
    ephemeral_subject_async,
    evict_keyring_member,
    mint_cap,
    parse_join_request,
)

# ── Registry ───────────────────────────────────────────────────────────────────
from starfish_spaces.registry import (
    SpaceEntry,
    SpacesDoc,
    add_joined_space,
    add_joined_space_with_cap,
    add_joined_space_with_link_access,
    add_space_member,
    broadcast_space_meta,
    build_space,
    create_space,
    move_space,
    on_space_meta,
    read_space_access,
    read_spaces,
    reconcile_space_meta,
    remove_joined_space,
    remove_space_member,
    reorder_spaces,
    update_spaces_doc,
    update_spaces_extra_field,
    write_space_access,
    write_spaces,
)

# ── Object index ───────────────────────────────────────────────────────────────
from starfish_spaces.object_index import (
    push_index_seed,
    read_object_tree,
    seed_space_object_index,
    update_object_index,
)

# ── Members ────────────────────────────────────────────────────────────────────
from starfish_spaces.members import (
    StoredSpaceInvite,
    accept_space_invite,
    add_device_to_space_keyring,
    clear_space_invite_store,
    create_space_invite_link,
    decode_space_invite_link,
    encode_space_invite_link,
    get_space_invite_entry,
    hydrate_space_invite_store,
    invite_to_space,
    join_space_by_link,
    make_join_request,
    recover_space_access,
    revoke_space_access,
    save_space_invite_entry,
    serialize_space_invite_store,
)

# ── Nodes ──────────────────────────────────────────────────────────────────────
from starfish_spaces.nodes import (
    CreateNodeInput,
    accept_node_invite,
    clear_node_invite_store,
    create_node,
    create_node_invite_link,
    decode_node_invite_link,
    encode_node_invite_link,
    get_node_invite_entry,
    hydrate_node_invite_store,
    invite_to_node,
    join_node_by_link,
    read_node_with_link_cap,
    revoke_node_access,
    save_node_invite_entry,
    serialize_node_invite_store,
    set_node_access,
    write_node_with_link_cap,
)

# ── Inbox ──────────────────────────────────────────────────────────────────────
from starfish_spaces.inbox import InboxElement, inbox_shard, inbox_shards, pull_inbox

# ── Identity link ──────────────────────────────────────────────────────────────
from starfish_spaces.identity_link import (
    IdentityLink,
    decode_identity_link,
    encode_identity_link,
    my_identity_link,
    verify_identity_link_binding,
    verify_identity_link_keys,
)

# ── Resource requests ──────────────────────────────────────────────────────────
from starfish_spaces.resource_requests import (
    PendingRequest,
    accept_resource_grant,
    accept_resource_request,
    clear_req_id_owner_store,
    hydrate_req_id_owner_store,
    reject_resource_request,
    scan_resource_grants,
    scan_resource_rejects,
    scan_resource_requests,
    save_req_id_owner,
    serialize_req_id_owner_store,
    submit_resource_request,
)

# ── Object directory ───────────────────────────────────────────────────────────
from starfish_spaces.object_directory import (
    ObjectDirectoryEntry,
    parse_object_directory_doc,
    read_object_directory,
)

# ── Lazy plugin imports (avoids pulling starfish_server into client contexts) ──

_LAZY_PLUGIN = {
    "create_spaces_role_enricher",
    "create_spaces_directory_server_plugin",
}


def __getattr__(name: str) -> object:
    if name in _LAZY_PLUGIN:
        from starfish_spaces import plugin as _plugin
        return getattr(_plugin, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# ── __all__ ────────────────────────────────────────────────────────────────────

__all__ = [
    # config & layout
    "SpaceLayout", "SpacesConfig", "KvAdapter", "Space", "ObjectType", "NodeAccess",
    "ObjectNode", "ObjectsIndex", "SealedBlob", "configure_spaces", "get_spaces_config",
    "default_space_layout", "default_user_id_from_ed_pub",
    "OBJECT_COLLECTIONS", "USER_ID_HEX_LENGTH", "RECIPIENT_LABEL_LEN",
    # session
    "Session", "BuildSessionOpts", "BuildLinkedSessionOpts", "LinkedIdentity",
    "build_session", "build_linked_session", "derive_session",
    "fingerprint_from_user_id", "generate_seed_words", "is_valid_seed", "owner_trusted_adders",
    # client helpers
    "DeviceKeys", "ClientOpts", "PublicProfile",
    "make_space_client", "make_anon_space_client", "cap_provider_for",
    "open_encryptor", "build_encryptor",
    "owner_ensure_keyring", "add_keyring_recipient_core",
    "add_space_keyring_recipient", "owner_ensure_space_keyring",
    "ensure_space_keyring_recipient",
    "is_already_present_recipient", "is_keyring_missing",
    "read_profile", "read_profiles", "write_profile", "ensure_pseudo", "ensure_profile_keys",
    "build_auth_headers",
    # keyed store
    "KeyedStore", "ComposedStore", "create_keyed_store", "create_composed_store",
    # space access error
    "SpaceAccessError",
    # space access store
    "SpaceAccessEntry",
    "configure_space_access_store", "hydrate_space_access_store",
    "get_space_access_entry", "save_space_access_entry", "remove_space_access_entry",
    "get_node_access_entry", "save_node_access_entry", "remove_node_access_entry",
    "get_node_stream_access_entry", "save_node_stream_access_entry", "remove_node_stream_access_entry",
    "get_node_keyring_access_entry", "save_node_keyring_access_entry", "remove_node_keyring_access_entry",
    "local_space_access_entries", "member_caps_from_store", "link_access_from_store",
    "clear_space_access_store", "clear_persisted_space_access",
    # account seal
    "seal_to_self", "unseal_from_self", "seal_to_recipient", "unseal_from_recipient",
    # request verify
    "sign_kem_sig", "verify_kem_sig",
    # CAS retry
    "run_cas",
    # objects
    "build_tree", "add_object",
    # node keyring
    "NodeKeyringRecipient",
    "owner_ensure_node_keyring", "open_node_encryptor", "build_node_encryptor",
    "add_node_keyring_recipient", "ensure_node_keyring_recipient", "remove_node_keyring_recipient",
    # space access resolver
    "NodeAccessHandle",
    "get_space_client", "get_node_stream_client", "get_node_access", "build_node_access",
    "clear_node_access_cache",
    # token types
    "JoinRequest", "SpaceInviteLinkToken", "NodeInviteBundle", "NodeInviteKind",
    "NodeInviteLinkToken", "ResourceRequest", "ResourceGrant", "ResourceReject",
    "StoredNodeInvite",
    # invite helpers
    "CapSubject", "adder_of", "mint_cap", "cap_nonce", "parse_join_request",
    "ephemeral_subject_async", "assert_cap_for_me", "evict_keyring_member",
    # registry
    "SpacesDoc", "SpaceEntry",
    "build_space", "on_space_meta", "broadcast_space_meta",
    "read_spaces", "update_spaces_doc", "update_spaces_extra_field", "write_spaces",
    "reorder_spaces", "read_space_access", "write_space_access",
    "add_space_member", "remove_space_member",
    "remove_joined_space", "move_space",
    "add_joined_space", "add_joined_space_with_cap", "add_joined_space_with_link_access",
    "create_space", "reconcile_space_meta",
    # object index
    "push_index_seed", "seed_space_object_index", "update_object_index", "read_object_tree",
    # members
    "StoredSpaceInvite",
    "make_join_request", "save_space_invite_entry", "get_space_invite_entry",
    "clear_space_invite_store", "serialize_space_invite_store", "hydrate_space_invite_store",
    "invite_to_space", "accept_space_invite",
    "encode_space_invite_link", "decode_space_invite_link", "create_space_invite_link",
    "join_space_by_link", "add_device_to_space_keyring",
    "recover_space_access", "revoke_space_access",
    # nodes
    "CreateNodeInput",
    "save_node_invite_entry", "get_node_invite_entry",
    "clear_node_invite_store", "serialize_node_invite_store", "hydrate_node_invite_store",
    "create_node", "set_node_access",
    "invite_to_node", "accept_node_invite", "revoke_node_access",
    "encode_node_invite_link", "decode_node_invite_link", "create_node_invite_link",
    "join_node_by_link", "read_node_with_link_cap", "write_node_with_link_cap",
    # inbox
    "InboxElement", "inbox_shard", "inbox_shards", "pull_inbox",
    # identity link
    "IdentityLink",
    "verify_identity_link_binding", "encode_identity_link", "decode_identity_link",
    "my_identity_link", "verify_identity_link_keys",
    # resource requests
    "PendingRequest",
    "save_req_id_owner", "serialize_req_id_owner_store",
    "hydrate_req_id_owner_store", "clear_req_id_owner_store",
    "submit_resource_request", "scan_resource_requests",
    "accept_resource_request", "reject_resource_request",
    "scan_resource_grants", "scan_resource_rejects", "accept_resource_grant",
    # object directory
    "ObjectDirectoryEntry", "parse_object_directory_doc", "read_object_directory",
    # lazy plugin exports
    "create_spaces_role_enricher", "create_spaces_directory_server_plugin",
]
