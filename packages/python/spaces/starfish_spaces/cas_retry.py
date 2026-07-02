"""CAS (compare-and-swap) retry helper.

Wraps a read-modify-write async function in a retry loop that retries on
``ConflictError`` (HTTP 409 / hash mismatch) up to ``MAX_ATTEMPTS`` times,
sleeping with jittered exponential backoff between attempts so replicas have
time to converge.  Non-conflict errors propagate immediately.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any, Awaitable, Callable, Coroutine, Optional, TypeVar

from starfish_sdk.types import ConflictError

T = TypeVar("T")

MAX_ATTEMPTS = 5
MAX_BACKOFF_MS = 800
_BASE_MS = 80


async def run_cas(
    fn: Callable[[], Coroutine[Any, Any, T]],
    *,
    sleep: Optional[Callable[[float], Awaitable[None]]] = None,
    rand: Optional[Callable[[], float]] = None,
) -> T:
    """Retry ``fn`` up to :data:`MAX_ATTEMPTS` times on :class:`ConflictError`.

    Between retries it sleeps with jittered exponential backoff
    (``min(80 * 2**(attempt-1), 800)`` ms plus up to 25% jitter), mirroring the
    TypeScript ``runCas``.

    Args:
        fn: An async callable with no arguments that performs one CAS attempt
            (read-then-write). Must be idempotent — it is called again from
            scratch on each retry (re-reads the current server state).
        sleep: Injectable async sleep (seconds); defaults to :func:`asyncio.sleep`.
            Useful to keep tests fast/deterministic.
        rand: Injectable ``[0, 1)`` source for jitter; defaults to
            :func:`random.random`.

    Returns:
        The value returned by the first successful invocation of ``fn``.

    Raises:
        ConflictError: if all attempts fail with a conflict.
        Any other exception raised by ``fn`` is propagated immediately.
    """
    _sleep = sleep if sleep is not None else asyncio.sleep
    _rand = rand if rand is not None else random.random

    last_err: ConflictError | None = None
    attempt = 0
    while attempt < MAX_ATTEMPTS:
        try:
            return await fn()
        except ConflictError as exc:
            last_err = exc
            attempt += 1
            if attempt >= MAX_ATTEMPTS:
                break
            base = min(_BASE_MS * (2 ** (attempt - 1)), MAX_BACKOFF_MS)
            jitter = _rand() * base * 0.25
            await _sleep((base + jitter) / 1000)
    raise last_err  # type: ignore[misc]


__all__ = ["run_cas", "MAX_ATTEMPTS"]
