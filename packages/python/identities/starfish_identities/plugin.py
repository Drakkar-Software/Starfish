"""Server plugin for the identities extension (Python mirror).

Registers a no-op ``device`` cap-validator with the
``starfish_server.create_cap_cert_role_resolver``. The validator is
intentionally a no-op for device caps: the underlying well-formedness
check (run at mint time inside ``mint_device_cap``) is already
sufficient.
"""

from __future__ import annotations

from typing import Any

from starfish_protocol.plugins import ServerPlugin


def _validate_device_cap(_cert: Any) -> None:
    """No-op validator — see module docstring."""


identities_server_plugin = ServerPlugin(
    name="starfish-identities",
    cap_validators={"device": _validate_device_cap},
)


__all__ = ["identities_server_plugin"]
