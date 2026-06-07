"""Generic issuer-bound public-share role enricher.

Generalizes the "public share keyed by a free ``{ownerId}``" pattern, where a
path like ``pubspaces/{ownerId}/{spaceId}/{docId}`` would let any signed cap
read any owner's public resource under a plain ``cap:read:<col>`` role. Gate on
synthesized roles instead, decided PURELY from the requester's cap (no store
read):

  - ``owner_role``  — owner managing their own public resource. Uses a DEVICE
                      cap, so ``auth.identity == ownerId``. Gates WRITES.
  - ``reader_role`` — a MEMBER/AUDIENCE cap the owner minted; the resolver emits
                      ``delegated:<issUserId>:<col>``, so grant read only when
                      the issuer is the path's owner. Gates READS.
  - ``writer_role`` — an owner-minted member cap that also carries write
                      authority (``cap:write:<col>`` from scope.ops). Gates
                      WRITES on non-registry docs.

Two subtleties (both were latent bugs in simpler share forms):

  - DEVICE caps never get a ``delegated:`` role (the resolver emits it for
    member/audience caps only). So the owner is granted ``reader_role``
    ALONGSIDE ``owner_role`` — otherwise the owner could write but not READ
    their own data.
  - A read/write link must NOT let a guest rewrite the registry doc. So
    ``writer_role`` is withheld when ``params[guard_param] == guard_value``
    (e.g. the ``_rooms`` registry) — guests post in rooms but only the owner
    manages the room list.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starfish_server.router.route_builder import AuthResult, RoleEnricher


def make_issuer_bound_role_enricher(
    *,
    owner_param: str,
    owner_role: str,
    reader_role: str,
    writer_role: str,
    collections: list[str],
    guard_param: str,
    guard_value: str,
) -> "RoleEnricher":
    """A RoleEnricher granting issuer-bound public-share roles from the
    requester's cap alone (no store access).

    :param owner_param: the path param holding the owner id (e.g. ``"ownerId"``).
    :param owner_role: role granted to the owner's own device cap.
    :param reader_role: role granted to the owner and to caps delegated by the
        owner for one of ``collections``.
    :param writer_role: role granted (in addition to ``reader_role``) to a
        delegated cap carrying ``cap:write:<col>`` for one of ``collections``,
        UNLESS the request targets the guard doc.
    :param collections: collections whose ``delegated:`` / ``cap:write:`` roles
        admit the share (e.g. ``["pubspace", "pubstream"]``).
    :param guard_param: the path param checked against ``guard_value`` to
        withhold ``writer_role`` (e.g. ``"docId"``).
    :param guard_value: the value of ``guard_param`` that withholds
        ``writer_role`` (e.g. ``"_rooms"``).
    """

    async def enricher(auth: "AuthResult", params: dict[str, str]) -> list[str]:
        owner_id = params.get(owner_param)
        if not owner_id or not auth.identity:
            return []
        roles: list[str] = []
        # Owner's own device cap (auth.identity == ownerId): full access. Grant
        # reader too — a device cap has no `delegated:` role, so without this the
        # owner couldn't read their own public resource.
        if auth.identity == owner_id:
            roles.append(owner_role)
            roles.append(reader_role)
        # A member/audience cap issued BY this owner → may read (and write
        # non-registry docs if it carries write). The resolver emits
        # `delegated:<iss>:<col>` for member/audience caps.
        delegated_by_owner = any(
            f"delegated:{owner_id}:{col}" in auth.roles for col in collections
        )
        if delegated_by_owner:
            roles.append(reader_role)
            can_write = any(
                f"cap:write:{col}" in auth.roles for col in collections
            )
            if params.get(guard_param) != guard_value and can_write:
                roles.append(writer_role)
        return roles

    return enricher
