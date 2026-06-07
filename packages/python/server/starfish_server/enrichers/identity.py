"""Identity-match RoleEnricher.

Grants a fixed role to a single configured identity. Generalizes the common
"platform admin" pattern (grant ``"admin"`` to the platform's root userId) into
a reusable primitive: any app that wants to elevate one well-known identity to a
named role can wire this enricher rather than hand-rolling the comparison.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starfish_server.router.route_builder import AuthResult, RoleEnricher


def make_identity_role_enricher(identity: str, role: str) -> "RoleEnricher":
    """Build a :class:`RoleEnricher` granting ``role`` when the authenticated
    ``auth.identity`` equals ``identity``.

    Returns ``[role]`` on an exact, non-empty identity match and ``[]`` otherwise
    (including when ``auth.identity`` is empty/anonymous). The match is on the
    cap-cert-bound userId, so only the holder of the configured identity's key
    material is ever elevated.

    Compose with other enrichers via
    :func:`starfish_server.enrichers.compose.compose_enrichers`.
    """

    async def enricher(auth: "AuthResult", params: dict[str, str]) -> list[str]:
        if auth.identity and auth.identity == identity:
            return [role]
        return []

    return enricher
