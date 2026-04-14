"""Client-side helper for reading a user's entitlement document."""

from __future__ import annotations

from starfish_sdk.client import StarfishClient
from starfish_sdk.types import StarfishHttpError


async def pull_entitlements(
    client: StarfishClient,
    user_id: str,
    path: str = "/pull/users/{user_id}/entitlements",
    field: str = "features",
) -> list[str]:
    """Fetch the list of feature slugs from a user's entitlement document.

    Returns an empty list if the document does not exist yet or the field is
    absent — callers never need to handle a 404.

    ::

        from starfish_sdk import pull_entitlements

        features = await pull_entitlements(client, user_id)
        # e.g. ["premium-package-1", "paid-cloud-sync"]

        if "paid-cloud-sync" in features:
            # unlock cloud sync UI
            pass

    :param client: An authenticated :class:`~starfish_sdk.client.StarfishClient`.
    :param user_id: The identity segment used in the entitlement collection path.
    :param path: Path template; ``{user_id}`` is replaced with ``user_id``.
        Defaults to ``"/pull/users/{user_id}/entitlements"``.
    :param field: Field name inside the document ``data`` object that holds the
        feature slug list.  Defaults to ``"features"``.
    :returns: List of feature slug strings, or an empty list if none found.
    """
    resolved_path = path.replace("{user_id}", user_id)
    try:
        result = await client.pull(resolved_path)
        data = result.data if isinstance(result.data, dict) else {}
        feature_list = data.get(field)
        if not isinstance(feature_list, list):
            return []
        return [f for f in feature_list if isinstance(f, str)]
    except StarfishHttpError as exc:
        if exc.status == 404:
            return []
        raise
