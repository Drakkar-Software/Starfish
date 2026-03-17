"""Filesystem-backed object store for local development and simple deployments."""


import os
import re
from asyncio import to_thread
from dataclasses import dataclass

import aiofiles
import aiofiles.os

from starfish_server.storage.base import AbstractObjectStore

# Keys may only contain alphanumeric chars, dots, underscores, hyphens, colons, at-signs,
# and forward slashes (used as directory separators). This mirrors the path-segment
# validation used in the HTTP router and prevents path traversal.
_VALID_KEY = re.compile(r"^[a-zA-Z0-9._:@\-/]+$")


def _validate_key(key: str) -> None:
    if not key or not _VALID_KEY.match(key) or ".." in key.split("/"):
        raise ValueError(f"Invalid storage key: {key!r}")


@dataclass
class FilesystemStorageOptions:
    """Configuration for the filesystem object store."""

    base_dir: str
    """Root directory for all stored objects, e.g. ``"./data"`` or ``"/var/starfish"``."""


class FilesystemObjectStore(AbstractObjectStore):
    """Object store backed by the local filesystem.

    Each key maps to a file at ``{base_dir}/{key}``. The ``base_dir`` is created
    on first write if it does not already exist.

    File reads and writes use ``aiofiles`` for non-blocking async I/O.
    Writes are atomic: data is written to a temporary ``.tmp`` sibling file
    and then renamed into place. Directory listing uses ``asyncio.to_thread``
    as ``os.walk`` has no async equivalent.

    This store is intended for local development and simple single-node
    deployments. For production, use :class:`~starfish_server.storage.s3.S3ObjectStore`.
    """

    def __init__(self, opts: FilesystemStorageOptions) -> None:
        self._base = os.path.abspath(opts.base_dir)

    def _path(self, key: str) -> str:
        _validate_key(key)
        return os.path.join(self._base, *key.split("/"))

    async def get_string(self, key: str) -> str | None:
        path = self._path(key)
        try:
            async with aiofiles.open(path, encoding="utf-8") as f:
                return await f.read()
        except FileNotFoundError:
            return None

    async def put(
        self,
        key: str,
        body: str,
        *,
        content_type: str | None = None,
        cache_control: str | None = None,
    ) -> None:
        path = self._path(key)
        await aiofiles.os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        try:
            async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
                await f.write(body)
            await aiofiles.os.replace(tmp, path)
        except Exception:
            # Clean up temp file on failure
            try:
                await aiofiles.os.remove(tmp)
            except OSError:
                pass
            raise

    async def list_keys(
        self,
        prefix: str,
        *,
        start_after: str | None = None,
        limit: int | None = None,
    ) -> list[str]:
        _validate_key(prefix)

        def _list() -> list[str]:
            prefix_path = os.path.join(self._base, *prefix.split("/"))
            # If the prefix path is a file (not a directory), return it if it matches
            if os.path.isfile(prefix_path):
                key = prefix
                if start_after is None or key > start_after:
                    return [key]
                return []

            results: list[str] = []
            if not os.path.isdir(prefix_path):
                return results

            for dirpath, _dirnames, filenames in os.walk(prefix_path):
                for fname in sorted(filenames):
                    if fname.endswith(".tmp"):
                        continue
                    abs_path = os.path.join(dirpath, fname)
                    # Convert back to key form
                    rel = os.path.relpath(abs_path, self._base)
                    key = rel.replace(os.sep, "/")
                    if not key.startswith(prefix):
                        continue
                    if start_after is not None and key <= start_after:
                        continue
                    results.append(key)

            results.sort()
            if limit is not None:
                results = results[:limit]
            return results

        return await to_thread(_list)

    async def delete(self, key: str) -> None:
        path = self._path(key)
        try:
            await aiofiles.os.remove(path)
        except FileNotFoundError:
            pass

    async def delete_many(self, keys: list[str]) -> None:
        for key in keys:
            await self.delete(key)
