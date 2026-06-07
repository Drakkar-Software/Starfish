"""Generic registry / TOFU owner-member role enricher.

Generalizes the per-app "registry doc doubles as the access record" pattern: a
collection keyed by a free ``{id}`` whose authoritative ``_registry`` document
stores ``{owner, members: [...userIds]}``. A plain cap role would let any
authenticated identity read/overwrite any id, so we gate access on two
synthesized roles decided from that owner-written record instead:

  - ``owner_role``  — the creator. With ``allow_tofu=True`` (default) the FIRST
                      writer to an id is granted ownership (trust-on-first-use),
                      which bootstraps resource creation.
  - ``member_role`` — owner OR any userId listed in ``members``.

``auth.identity`` is the cap-cert userId, and the registry stores those same
userIds — no central issuer is involved (decentralized TOFU).

Security properties (preserved exactly from the originating app enrichers):

  - Fails CLOSED on any store error (network/IAM/throttling): if
    ``store.get_string`` RAISES, the exception propagates (the resolver turns it
    into a 500). Letting transient outages fall through to "no registry yet ⇒
    open TOFU" would let an attacker who can induce store errors take over
    established resources.
  - ``id_pattern.fullmatch`` (NOT ``match``) guards against a trailing-newline
    bypass — ``re.match``'s ``$`` matches before a trailing ``\n``, so ``foo\n``
    would slip through ``.match()`` and could perturb downstream subject
    reconstruction. The default pattern is ``^[a-zA-Z0-9_-]+$``.
  - An owner-less / unparseable stored doc fails CLOSED (returns ``[]``) rather
    than re-opening TOFU and inviting takeover by the next writer.

The ``allow_tofu=False`` strict variant (used by SSE/events paths) requires a
recorded role in an existing registry doc, so a caller can't subscribe to a
not-yet-existing id and silently receive the legit owner's events once that
resource gets created.
"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starfish_server.router.route_builder import AuthResult, RoleEnricher
    from starfish_server.storage.base import AbstractObjectStore

logger = logging.getLogger(__name__)

# Default id charset — tighter than starfish's SAFE_PARAM. Disallows ``.``,
# ``:``, ``@`` so ids cannot collide after downstream sanitization (e.g. a
# NATS-subject sanitizer mapping ``[^a-zA-Z0-9\-_~%] → '-'``).
DEFAULT_SAFE_ID = re.compile(r"^[a-zA-Z0-9_-]+$")


def _access_from_registry(raw: str) -> tuple[str | None, list[str]]:
    """Owner + member roster recorded in a registry doc.

    Tolerates both the stored sync-document shape (``{"data": {...}}``) and a
    bare object.
    """
    try:
        doc = json.loads(raw)
    except (ValueError, TypeError):
        return None, []
    data = doc["data"] if isinstance(doc, dict) and "data" in doc else doc
    if not isinstance(data, dict):
        return None, []
    owner = data.get("owner") if isinstance(data.get("owner"), str) else None
    members_raw = data.get("members")
    members = (
        [m for m in members_raw if isinstance(m, str)]
        if isinstance(members_raw, list)
        else []
    )
    return owner, members


def make_registry_role_enricher(
    store: "AbstractObjectStore",
    *,
    id_param: str,
    registry_path: str,
    owner_role: str,
    member_role: str,
    allow_tofu: bool = True,
    id_pattern: "re.Pattern[str]" = DEFAULT_SAFE_ID,
) -> "RoleEnricher":
    """A RoleEnricher granting ``owner_role`` / ``member_role`` from an
    authoritative owner-written registry document.

    :param store: the object store to read the registry document from.
    :param id_param: the path param holding the resource id (e.g. ``"productId"``).
    :param registry_path: storage path template with a ``{id}`` placeholder for
        the resource id (e.g. ``"products/{id}/_registry"``).
    :param owner_role: role granted to the owner (e.g. ``"product:owner"``).
    :param member_role: role granted to owner + members (e.g. ``"product:member"``).
    :param allow_tofu: when ``True`` (default), a missing registry doc grants
        ``[owner_role, member_role]`` (trust-on-first-use). When ``False``, a
        missing doc grants ``[]`` (strict; used by SSE/events paths).
    :param id_pattern: compiled regex the id must ``fullmatch``; default
        :data:`DEFAULT_SAFE_ID`.
    """

    async def enricher(auth: "AuthResult", params: dict[str, str]) -> list[str]:
        resource_id = params.get(id_param)
        if not resource_id or not auth.identity:
            return []
        # fullmatch — guard against trailing-newline bypass.
        if not id_pattern.fullmatch(resource_id):
            return []
        # store.get_string is contracted to return None for missing keys; any
        # raise here means a real store error and we fail closed (the resolver
        # returns 500 → client retries; better than silently granting TOFU
        # access during an outage). Do NOT swallow.
        raw = await store.get_string(registry_path.replace("{id}", resource_id))
        if raw is None:
            return [owner_role, member_role] if allow_tofu else []
        owner, members = _access_from_registry(raw)
        if owner is None:
            # Owner-less / unparseable stored doc → fail closed. Re-opening TOFU
            # here would invite takeover by the next writer.
            logger.warning(
                "registry %s has no owner field; denying.", resource_id
            )
            return []
        if owner == auth.identity:
            return [owner_role, member_role]
        if auth.identity in members:
            return [member_role]
        return []

    return enricher
