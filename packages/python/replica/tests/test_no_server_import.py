"""Layering: the scheduling/channel seam must not reference ``starfish_server``.

## Why this is a static check and not a ``sys.modules`` check

The TS package gets this property from its bundler: ``./space`` is a separate
esbuild entry, so importing ``@drakkar.software/starfish-replica/space`` never
evaluates the root ``index.ts`` and the bundle contains no ``starfish-server``
code. That mattered concretely — React Native's Metro cannot resolve the Node
builtins (``node:dns/promises``) that ``starfish-server`` pulls in.

Python has neither a bundler nor that constraint, and importing ANY submodule
(``starfish_replica.space``) evaluates the package's ``__init__.py`` first,
which imports ``manager``/``http_channel`` and therefore ``starfish_server``.
A runtime "``starfish_server`` never lands in ``sys.modules``" assertion would
therefore fail for a reason that is not a defect — and it would be testing a
property nobody needs, since ``starfish-server`` is a hard, non-optional
dependency of this package in both languages (see ``pyproject.toml`` and the
TS ``package.json``: it sits in ``dependencies``, not ``peerDependencies``).

What IS worth enforcing is the source-level layering that mirrors the TS
module boundaries: ``channel.py``/``scheduler.py``/``config.py`` — and every
module under ``space/`` except its port — must not name ``starfish_server``.
That keeps the seam honest, keeps a future extraction of the scheduler into
its own distribution possible, and catches the easy mistake of reaching for
``push()`` or ``AbstractObjectStore`` from the generic scheduling layer.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_PKG = Path(__file__).resolve().parent.parent / "starfish_replica"

# Modules that make up the generic (non-HTTP) seam, plus the whole space
# subpackage — none of it has any business touching server-side code.
SERVER_FREE_MODULES = [
    "channel.py",
    "scheduler.py",
    "config.py",
    "space/__init__.py",
    "space/plan.py",
    "space/port.py",
    "space/mirror_channel.py",
]

# Only `space/port.py` may import starfish_spaces — that isolation is what
# keeps the channel unit-testable against a fake port (see port.py's docstring).
SPACES_FREE_MODULES = ["space/plan.py", "space/mirror_channel.py", "channel.py", "scheduler.py"]


def _imported_modules(path: Path) -> set[str]:
    """Every module name imported by ``path`` (``import x`` / ``from x import y``)."""
    tree = ast.parse(path.read_text(), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _references_server(path: Path) -> bool:
    return any(
        name == "starfish_server" or name.startswith("starfish_server.")
        for name in _imported_modules(path)
    )


@pytest.mark.parametrize("module", SERVER_FREE_MODULES)
def test_seam_module_does_not_import_starfish_server(module: str):
    assert not _references_server(_PKG / module), (
        f"{module} imports starfish_server — the generic scheduling seam must stay "
        "free of server-side code (see this module's docstring)."
    )


def test_scheduler_does_not_import_http_channel():
    # The specific coupling the split exists to prevent: scheduling must not
    # know about the HTTP data path.
    imported = _imported_modules(_PKG / "scheduler.py")
    assert not any("http_channel" in name for name in imported)


def test_channel_does_not_import_scheduler_or_http_channel():
    # channel.py defines the seam; it must not depend on either implementation
    # side, or the abstraction is circular.
    imported = _imported_modules(_PKG / "channel.py")
    assert not any("http_channel" in name or "scheduler" in name for name in imported)


def test_http_channel_does_import_starfish_server():
    # The control. http_channel legitimately needs the server's ObjectStore and
    # push(); if this ever came back False the AST probe itself would be broken
    # and every assertion above would be vacuously true.
    assert _references_server(_PKG / "http_channel.py")


def test_every_seam_module_actually_exists():
    # Guards against a rename silently emptying the parametrised tests above.
    for module in SERVER_FREE_MODULES + SPACES_FREE_MODULES:
        assert (_PKG / module).is_file(), f"{module} not found — update the module lists"


# ── starfish_spaces isolation inside space/ ──────────────────────────────────


def _references_spaces(path: Path) -> bool:
    return any(
        name == "starfish_spaces" or name.startswith("starfish_spaces.")
        for name in _imported_modules(path)
    )


@pytest.mark.parametrize("module", SPACES_FREE_MODULES)
def test_only_the_port_imports_starfish_spaces(module: str):
    assert not _references_spaces(_PKG / module), (
        f"{module} imports starfish_spaces directly — route it through SpacePort "
        "instead, or the mirror channel stops being testable against a fake port."
    )


def test_the_port_does_import_starfish_spaces():
    # Control for the parametrised test above.
    assert _references_spaces(_PKG / "space" / "port.py")


def test_space_barrel_does_not_import_http_channel():
    # Importing the space subpackage should not drag the HTTP data path in.
    imported = _imported_modules(_PKG / "space" / "__init__.py")
    assert not any("http_channel" in name or "manager" in name for name in imported)
