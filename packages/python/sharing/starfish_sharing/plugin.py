"""Server plugin for the sharing extension (Python mirror).

Registers a ``member`` cap-validator (member-self, member-multi-collection,
member-private-path, member-members-not-denied, member-keyring-not-denied) and
an ``audience`` cap-validator (the public-link kind: single-collection +
owner-namespace barriers, no single-subject rules). Without the ``audience``
validator, strict-kind dispatch rejects every audience cap with HTTP 401.
"""

from __future__ import annotations

from starfish_protocol.plugins import ServerPlugin

from .cap_mint import assert_audience_cap_shape, assert_member_cap_shape


sharing_server_plugin = ServerPlugin(
    name="starfish-sharing",
    cap_validators={
        "member": assert_member_cap_shape,
        "audience": assert_audience_cap_shape,
    },
)


__all__ = ["sharing_server_plugin"]
