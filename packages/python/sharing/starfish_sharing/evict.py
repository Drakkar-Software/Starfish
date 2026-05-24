"""One-call member eviction.

Removing a member from the keyring (``remove_recipient``, which rotates the epoch
for forward secrecy) does NOT stop them writing — write authority is cap-based, so
the member keeps posting until their cap is revoked. Full eviction is therefore two
cryptographic steps plus a roster update, and doing only one is an easy footgun.

``evict_member`` composes all three behind explicit ``rotate`` / ``revoke`` flags so
both effects are visible at the call site. It stays transport- and ledger-agnostic:
the caller supplies a ``submit_revocation`` callback (the revocation list's
``generation`` must strictly increase per issuer, which only the caller can track)
and the prior revoked entries to carry forward.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Awaitable, Callable, Optional

from starfish_keyring import AdderKeys, remove_recipient
from starfish_protocol import build_revocation_list

from starfish_sharing.directory import remove_member_entry

if TYPE_CHECKING:  # pragma: no cover - typing only
    from starfish_sdk.client import StarfishClient


async def evict_member(
    client: "StarfishClient",
    *,
    members_collection: str,
    member: dict[str, Any],
    iss_ed_pub_hex: str,
    iss_ed_priv_hex: str,
    generation: int,
    submit_revocation: Callable[[dict[str, Any]], Awaitable[None]],
    keyring_collection: Optional[str] = None,
    adder: Optional[AdderKeys] = None,
    trusted_adders: Optional[list[str]] = None,
    prior_revoked: Optional[list[dict[str, Any]]] = None,
    rotate: bool,
    revoke: bool,
) -> dict[str, Any]:
    """Evict a member: optionally revoke their cap, optionally rotate them out of the
    keyring, and (on any eviction) drop their directory entry.

    ``member`` is ``{"sub", "nonce", "exp", "subKem"}``. Revocation runs FIRST so a
    still-valid cap cannot squeeze a write in between the rotate and the revoke. With
    both flags set this is the full, footgun-free eviction. Returns
    ``{"newEpoch": <int>?, "revoked": <bool>}``.

    For a plaintext / cap-only collection there is no keyring, so eviction is
    revoke-only: pass ``rotate=False, revoke=True`` and omit ``keyring_collection`` /
    ``adder`` / ``trusted_adders``. The roster entry (the published cap) is still dropped —
    a no-op when no roster exists (e.g. the stateless, out-of-band flow).
    """
    if not rotate and not revoke:
        return {"revoked": False}

    revoked = False
    if revoke:
        revocation_list = build_revocation_list(
            iss_ed_pub_hex,
            iss_ed_priv_hex,
            generation,
            revoked=[
                *(prior_revoked or []),
                {"sub": member["sub"], "nonce": member["nonce"], "exp": member["exp"]},
            ],
        )
        await submit_revocation(revocation_list)
        revoked = True

    result: dict[str, Any] = {"revoked": revoked}
    if rotate:
        if keyring_collection is None or adder is None or trusted_adders is None:
            raise ValueError(
                "evict_member: rotate=True requires keyring_collection, adder, and "
                "trusted_adders (omit them only for revoke-only eviction of a "
                "plaintext / cap-only collection)"
            )
        rotated = await remove_recipient(
            client,
            keyring_collection,
            [member["subKem"]],
            adder,
            trusted_adders=trusted_adders,
        )
        result["newEpoch"] = rotated["newEpoch"]

    # Any eviction drops the roster entry — under membership-bound room writes this
    # also removes the member's `chat:member` write grant.
    await remove_member_entry(client, members_collection, member["nonce"])

    return result
