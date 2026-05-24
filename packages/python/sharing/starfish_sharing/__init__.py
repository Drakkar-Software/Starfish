"""``starfish-sharing`` — member-cap extension.

Public surface: member cap-cert minting with the
``read_only``/``writer``/``admin`` scope presets, the per-collection
``_members`` directory, and the server plugin.
"""

from starfish_sharing.cap_mint import (
    AudienceMintOpts,
    MintOpts,
    ScopePreset,
    assert_audience_cap_shape,
    assert_member_cap_shape,
    mint_audience_cap,
    mint_member_cap,
    scopes,
)
from starfish_sharing.public_link import (
    ParsedPublicLink,
    PublicLink,
    create_public_link,
    parse_public_link,
    redeem_public_link,
)
from starfish_sharing.directory import (
    Directory,
    DirectoryEntry,
    ListDirectoryOpts,
    add_member_entry,
    fetch_member_caps,
    fetch_my_member_cap,
    list_members,
    members_path_for,
    publish_member_cap,
    remove_member_entry,
    unpublish_member_cap,
)
from starfish_sharing.evict import evict_member


def __getattr__(name: str):
    """Lazy import of ``sharing_server_plugin`` so apps that only use the
    client-side helpers don't pay the ``starfish_server`` import cost.
    """
    if name == "sharing_server_plugin":
        from starfish_sharing.plugin import sharing_server_plugin as _p
        return _p
    raise AttributeError(f"module 'starfish_sharing' has no attribute {name!r}")

__all__ = [
    "MintOpts",
    "AudienceMintOpts",
    "ScopePreset",
    "assert_member_cap_shape",
    "assert_audience_cap_shape",
    "mint_member_cap",
    "mint_audience_cap",
    "scopes",
    "PublicLink",
    "ParsedPublicLink",
    "create_public_link",
    "parse_public_link",
    "redeem_public_link",
    "Directory",
    "DirectoryEntry",
    "ListDirectoryOpts",
    "add_member_entry",
    "list_members",
    "members_path_for",
    "remove_member_entry",
    "publish_member_cap",
    "fetch_member_caps",
    "fetch_my_member_cap",
    "unpublish_member_cap",
    "evict_member",
    "sharing_server_plugin",
]
