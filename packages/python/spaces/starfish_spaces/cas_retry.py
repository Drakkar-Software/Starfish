"""CAS (compare-and-swap) retry helper.

Wraps a read-modify-write async function in a retry loop that retries on
``ConflictError`` (HTTP 409 / hash mismatch) up to ``MAX_ATTEMPTS`` times.
Non-conflict errors propagate immediately.
"""

from __future__ import annotations

from typing import Any, Callable, Coroutine, TypeVar

from starfish_sdk.types import ConflictError

T = TypeVar("T")

MAX_ATTEMPTS = 3


async def run_cas(fn: Callable[[], Coroutine[Any, Any, T]]) -> T:
    """Retry ``fn`` up to 3 times on :class:`ConflictError`.

    Args:
        fn: An async callable with no arguments that performs one CAS attempt
            (read-then-write). Must be idempotent — it is called again from
            scratch on each retry (re-reads the current server state).

    Returns:
        The value returned by the first successful invocation of ``fn``.

    Raises:
        ConflictError: if all 3 attempts fail with a conflict.
        Any other exception raised by ``fn`` is propagated immediately.
    """
    last_err: ConflictError | None = None
    for _ in range(MAX_ATTEMPTS):
        try:
            return await fn()
        except ConflictError as exc:
            last_err = exc
    raise last_err  # type: ignore[misc]


__all__ = ["run_cas", "MAX_ATTEMPTS"]
