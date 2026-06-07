"""Cross-language decision-table vectors for make_registry_role_enricher.

Shares ``tests/test-vectors/registry-role-enricher.json`` with the TS suite
(``packages/ts/sharing/tests/registry-role-enricher-vectors.test.ts``) so the
two implementations cannot drift on the registry/TOFU decision matrix. The
fail-closed (store-raises) and trailing-newline cases stay in
``test_registry_role_enricher.py`` — they can't be expressed as static data.
"""

import json
import pathlib

import pytest

from starfish_server.router.route_builder import AuthResult
from starfish_server.storage.memory import MemoryObjectStore
from starfish_sharing import make_registry_role_enricher

_VECTORS = json.loads(
    (
        pathlib.Path(__file__).parent.parent.parent.parent.parent
        / "tests"
        / "test-vectors"
        / "registry-role-enricher.json"
    ).read_text()
)


@pytest.mark.parametrize("case", _VECTORS["cases"], ids=[c["name"] for c in _VECTORS["cases"]])
async def test_registry_vector(case):
    store = MemoryObjectStore(data={})
    path = _VECTORS["registryPath"].replace("{id}", case["id"])
    if "registryRaw" in case:
        store._data[path] = case["registryRaw"]
    elif case.get("registry") is not None:
        store._data[path] = json.dumps(case["registry"])

    enricher = make_registry_role_enricher(
        store,
        id_param=_VECTORS["idParam"],
        registry_path=_VECTORS["registryPath"],
        owner_role=_VECTORS["ownerRole"],
        member_role=_VECTORS["memberRole"],
        allow_tofu=case["allowTofu"],
    )
    roles = await enricher(
        AuthResult(identity=case["authIdentity"], roles=[]),
        {_VECTORS["idParam"]: case["id"]},
    )
    assert roles == case["expected"]
