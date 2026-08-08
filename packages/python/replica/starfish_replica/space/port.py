"""The ONLY module under ``space/`` that imports ``starfish_spaces``.

``SpaceMirrorChannel`` (``mirror_channel.py``) depends on :class:`SpacePort`,
not on ``starfish_spaces`` directly — so it stays unit-testable with a fake
in-memory port (no ``unittest.mock``, matching this monorepo's hand-rolled
fake-client idiom, e.g. ``packages/python/spaces/tests/test_registry_cas.py``).

Mirrors the TS package's ``space/port.ts``, with three signature differences
absorbed here rather than leaking into the channel — the Python and TS
``starfish_spaces``/``starfish-spaces`` APIs are not identical:

1. ``read_spaces(client, session)`` takes a client first and returns a
   ``SpacesDoc`` OBJECT (``.spaces`` attribute), where TS's ``readSpaces``
   returns a plain ``{ spaces }`` record.
2. ``read_object_tree(client, session, space_id)`` takes three args, and —
   the important one — returns a NESTED tree (``build_tree``), while TS's
   identically-named ``readObjectTree`` returns a FLAT ``ObjectNode[]`` (it
   calls ``readIndexObjects``, not ``buildTree``; the TS name is misleading).
   This port flattens, so both languages' channels see every node. Without
   the flatten, a non-root node would be invisible to the planner and the
   channel would create a duplicate alongside it.
3. ``get_node_access(session, space_id, node_id, node)`` orders its parameters
   differently from TS's ``getNodeAccess(spaceId, nodeId, node, session)``.
   ``node`` carries the ``{"access", "enc"}`` axes and is NOT optional in
   practice: without it the resolver cannot tell a plaintext node from an
   encrypted one and hands back an encryptor for both (see
   ``starfish_spaces.space_access``'s Tier 0). ``push_node_doc`` seals on
   ``handle.encryptor is not None``, so an unpassed ``node`` is what turns a
   plaintext collection into one holding ciphertext.

It also supplies something the TS port gets for free: ``push_node_doc``.
TS's ``NodeAccessHandle`` owns a ``push()`` that does the whole
pull → decrypt → mutate → encrypt → push CAS dance. Python's
``NodeAccessHandle`` (``space_access.py``) is a plain dataclass
(``client``/``encryptor``/``is_owner_open``) with no such method and no
equivalent anywhere in the package, so the port implements it here on top of
``starfish_spaces.cas_retry.run_cas``. Note ``KeyringEncryptor.encrypt`` /
``.decrypt`` are SYNCHRONOUS in Python (unlike TS) and must not be awaited.
"""

from __future__ import annotations

import asyncio
import dataclasses
from typing import Any, Awaitable, Callable, Optional, Protocol

from starfish_spaces.cas_retry import run_cas
from starfish_spaces.node_keyring import open_node_encryptor as sf_open_node_encryptor
from starfish_spaces.node_keyring import owner_ensure_node_keyring as sf_owner_ensure_node_keyring
from starfish_spaces.nodes import create_node as sf_create_node
from starfish_spaces.nodes import set_node_access as sf_set_node_access
from starfish_spaces.object_index import read_object_tree as sf_read_object_tree
from starfish_spaces.registry import create_space as sf_create_space
from starfish_spaces.registry import read_spaces as sf_read_spaces
from starfish_spaces.space_access import NodeAccessHandle
from starfish_spaces.space_access import get_node_access as sf_get_node_access
from starfish_spaces.space_access import get_space_client as sf_get_space_client

__all__ = [
    "SpacePort",
    "NodeAccessHandle",
    "default_space_port",
    "find_or_create_space",
    "flatten_object_tree",
]


def _as_dict(obj: Any) -> dict[str, Any]:
    """Normalize a dataclass/``Space``/plain-dict node or space into a dict.

    ``to_dict`` first: a type that ships one (e.g. ``ObjectTreeNode``) uses it
    to rename fields to their wire form, which :func:`dataclasses.asdict`
    would not do.
    """
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if hasattr(obj, "__dict__"):
        return dict(vars(obj))
    return {
        slot: getattr(obj, slot)
        for slot in getattr(obj, "__slots__", ())
        if hasattr(obj, slot)
    }


def flatten_object_tree(nodes: Any) -> list[dict[str, Any]]:
    """Depth-first flatten of ``read_object_tree``'s nested result.

    See this module's docstring, point 2: Python builds a tree where TS returns
    a flat list. Flattening here is what makes the two channels equivalent.
    """
    out: list[dict[str, Any]] = []

    def walk(items: Any) -> None:
        for item in items or ():
            data = _as_dict(item)
            out.append(data)
            walk(data.get("children") or ())

    walk(nodes)
    return out


class SpacePort(Protocol):
    """The subset of ``starfish_spaces``' space/node API the mirror channel needs."""

    async def read_spaces(self, session: Any) -> list[dict[str, Any]]:
        """All of the session identity's spaces, as ``{"id", "name"}`` dicts."""
        ...

    async def create_space(self, session: Any, name: str) -> dict[str, Any]:
        ...

    async def read_object_tree(self, session: Any, space_id: str) -> list[dict[str, Any]]:
        """FLAT list of every node in the space, as ``{"id", "type"}`` dicts.

        Each node also carries its STORED ``access``/``enc`` axes when the
        object index recorded them — it omits them when they are the defaults
        (``"space"`` / ``False``), so absent means default, not unknown.
        :class:`~starfish_replica.space.mirror_channel.SpaceMirrorChannel`
        reads them to detect a tier flip that happened while it was not
        running.
        """
        ...

    async def create_node(self, session: Any, space_id: str, inp: dict[str, Any]) -> dict[str, Any]:
        ...

    async def set_node_access(
        self, session: Any, space_id: str, node_id: str, patch: dict[str, Any]
    ) -> None:
        """Patch a node's STORED ``access``/``enc`` in the object index.

        The index is not just bookkeeping: Infra's public-objects projection
        reads ``access`` off it and re-publishes every ``"public"`` node's id,
        title and type into a world-readable index. A node left recorded as
        ``"public"`` after its content was migrated to private therefore keeps
        being advertised to anonymous callers forever.

        ``starfish_spaces`` rejects the invalid ``public`` + ``enc``
        combination internally, and normalizes the same way ``create_node``
        does — it DROPS ``access`` when it is ``"space"`` and ``enc`` when
        false — so a patched node is indistinguishable from one created at
        that tier.
        """
        ...

    async def get_node_access(
        self,
        session: Any,
        space_id: str,
        node_id: str,
        node: Optional[dict[str, Any]] = None,
    ) -> NodeAccessHandle:
        """Resolve the client (+ encryptor, if the node is encrypted) for a node.

        ``node`` is the ``{"access", "enc"}`` pair the node was created with.
        Always pass it — see this module's docstring, point 3.
        """
        ...

    async def get_isolated_node_access(
        self, session: Any, space_id: str, node_id: str
    ) -> NodeAccessHandle:
        """Resolve a handle whose encryptor is the node's OWN keyring (the
        isolated tier): ensure the per-node keyring exists, then open it. Unlike
        :meth:`get_node_access`, never falls back to the space keyring."""
        ...

    async def push_node_doc(
        self,
        handle: NodeAccessHandle,
        pull_path: str,
        push_path: str,
        mutator: Callable[[Any], Any],
        node: Optional[dict[str, Any]] = None,
    ) -> None:
        """CAS read-modify-write one node's content through ``handle``."""
        ...


class _DefaultSpacePort:
    """The real :class:`SpacePort`, bound to ``starfish_spaces``."""

    async def read_spaces(self, session: Any) -> list[dict[str, Any]]:
        doc = await sf_read_spaces(session.account_client, session)
        return [_as_dict(space) for space in (doc.spaces or [])]

    async def create_space(self, session: Any, name: str) -> dict[str, Any]:
        return _as_dict(await sf_create_space(session, name))

    async def read_object_tree(self, session: Any, space_id: str) -> list[dict[str, Any]]:
        tree = await sf_read_object_tree(session.content_client, session, space_id)
        return flatten_object_tree(tree)

    async def create_node(self, session: Any, space_id: str, inp: dict[str, Any]) -> dict[str, Any]:
        return _as_dict(await sf_create_node(session, space_id, inp))

    async def set_node_access(
        self, session: Any, space_id: str, node_id: str, patch: dict[str, Any]
    ) -> None:
        await sf_set_node_access(session, space_id, node_id, patch)

    async def get_node_access(
        self,
        session: Any,
        space_id: str,
        node_id: str,
        node: Optional[dict[str, Any]] = None,
    ) -> NodeAccessHandle:
        return await sf_get_node_access(session, space_id, node_id, node)

    async def get_isolated_node_access(
        self, session: Any, space_id: str, node_id: str
    ) -> NodeAccessHandle:
        # Never through sf_get_node_access: its owner tier silently falls back to
        # the SPACE keyring when the node keyring is missing, sealing isolated
        # content under the key every space member holds. This raises instead.
        await sf_owner_ensure_node_keyring(
            session.content_client, session, space_id, node_id, session.layout
        )
        encryptor = await sf_open_node_encryptor(
            session.content_client, session, space_id, node_id, session.layout
        )
        return NodeAccessHandle(
            client=await sf_get_space_client(session, space_id),
            encryptor=encryptor,
            is_owner_open=True,
        )

    async def push_node_doc(
        self,
        handle: NodeAccessHandle,
        pull_path: str,
        push_path: str,
        mutator: Callable[[Any], Any],
        node: Optional[dict[str, Any]] = None,
    ) -> None:
        # Defence in depth. The resolver's Tier 0 already refuses to build an
        # encryptor for a plaintext node, but this is the last line before bytes
        # leave the process: a plaintext node reaching here WITH an encryptor
        # means something upstream (a custom SpacePort, a future refactor that
        # drops the `node` argument again) has re-opened the hole, and the
        # failure mode is silent — a 200 from a collection the server declares
        # `encryption="none"`, world-readable, unrecoverable once written. Fail
        # loudly instead.
        if node is not None and not node.get("enc") and handle.encryptor is not None:
            raise RuntimeError(
                f"push_node_doc: refusing to seal a plaintext node ({push_path}). "
                "The handle carries an encryptor but the node declares enc=False — "
                "writing here would put ciphertext in a plaintext collection."
            )

        async def attempt() -> None:
            try:
                res = await handle.client.pull(pull_path)
                current = res.data if hasattr(res, "data") else None
                base_hash = res.hash if hasattr(res, "hash") else None
            except Exception:
                # No document yet (404) or an unreadable one — treat as absent
                # and write from scratch, same as the TS handle's own push().
                current = None
                base_hash = None

            if current is not None and handle.encryptor is not None:
                # KeyringEncryptor.decrypt is SYNCHRONOUS in Python.
                current = handle.encryptor.decrypt(current)

            nxt = mutator(current)
            if nxt is None:
                return  # mutator signalled no-op

            payload = handle.encryptor.encrypt(nxt) if handle.encryptor is not None else nxt
            await handle.client.push(push_path, payload, base_hash)

        await run_cas(attempt)


default_space_port: SpacePort = _DefaultSpacePort()


# In-flight find-or-create calls, keyed by ``{user_id}:{name}``, so two
# concurrent callers racing on the same (session, name) coalesce into one
# actual read+create instead of each independently missing the not-yet-created
# space and both calling create_space. This only protects against in-process
# concurrency (e.g. a scheduled sync and an interactive action overlapping in
# the same app session) — it cannot prevent two different devices from racing
# the same identity's space registry, which would need server-side idempotent
# creation.
_in_flight_find_or_create: dict[str, "asyncio.Task[dict[str, Any]]"] = {}


async def find_or_create_space(
    session: Any,
    name: str,
    port: Optional[SpacePort] = None,
) -> dict[str, Any]:
    """Find one of the session's spaces by name, creating it on first use.

    TOFU-first-writer semantics apply exactly like every other
    ``starfish_spaces`` space — the caller is always this identity's own
    device, so it is always the legitimate owner on first creation.
    """
    port = port or default_space_port
    key = f"{getattr(session, 'user_id', '')}:{name}"

    in_flight = _in_flight_find_or_create.get(key)
    if in_flight is not None:
        return await in_flight

    async def run() -> dict[str, Any]:
        spaces = await port.read_spaces(session)
        for space in spaces:
            if space.get("name") == name:
                return space
        return await port.create_space(session, name)

    task: "asyncio.Task[dict[str, Any]]" = asyncio.ensure_future(run())
    _in_flight_find_or_create[key] = task
    try:
        return await task
    finally:
        _in_flight_find_or_create.pop(key, None)
