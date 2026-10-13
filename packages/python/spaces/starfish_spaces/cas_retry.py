"""CAS (compare-and-swap) retry helper.

Wraps a read-modify-write async function in a retry loop that retries on
``ConflictError`` (HTTP 409 / hash mismatch) up to ``MAX_ATTEMPTS`` times,
sleeping with jittered exponential backoff between attempts so replicas have
time to converge.  Non-conflict errors propagate immediately.
"""

from __future__ import annotations

import asyncio
import inspect
import random
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Coroutine, Optional, TypeVar, Union

from starfish_sdk.types import ConflictError

T = TypeVar("T")

MAX_ATTEMPTS = 5
MAX_BACKOFF_MS = 800
_BASE_MS = 80


@dataclass(frozen=True)
class CasHint:
    """Hint passed to the CAS callback on each attempt."""

    current_hash: str
    attempt: int


def _fn_accepts_cas_hint(fn: Callable[..., Any]) -> bool:
    params = list(inspect.signature(fn).parameters.values())
    if not params:
        return False
    first = params[0]
    return first.kind in (
        inspect.Parameter.POSITIONAL_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
    )


async def run_cas(
    fn: Union[
        Callable[[], Coroutine[Any, Any, T]],
        Callable[[CasHint], Coroutine[Any, Any, T]],
    ],
    *,
    sleep: Optional[Callable[[float], Awaitable[None]]] = None,
    rand: Optional[Callable[[], float]] = None,
) -> T:
    """Retry ``fn`` up to :data:`MAX_ATTEMPTS` times on :class:`ConflictError`.

    Between retries it sleeps with jittered exponential backoff
    (``min(80 * 2**(attempt-1), 800)`` ms plus up to 25% jitter), mirroring the
    TypeScript ``runCas``.

    Args:
        fn: An async callable that performs one CAS attempt (read-then-write).
            If it accepts one positional argument, each invocation receives a
            :class:`CasHint` with the authoritative ``current_hash`` from the
            previous conflict (or ``""`` on the first attempt) and a zero-based
            ``attempt`` index. Zero-argument callables are unchanged. Must be
            idempotent — it is called again from scratch on each retry.
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
    passes_hint = _fn_accepts_cas_hint(fn)

    current_hash = ""
    attempt = 0
    while attempt < MAX_ATTEMPTS:
        try:
            if passes_hint:
                return await fn(CasHint(current_hash=current_hash, attempt=attempt))
            return await fn()
        except ConflictError as exc:
            attempt += 1
            if attempt >= MAX_ATTEMPTS:
                raise exc
            current_hash = exc.current_hash
            base = min(_BASE_MS * (2 ** (attempt - 1)), MAX_BACKOFF_MS)
            jitter = _rand() * base * 0.25
            await _sleep((base + jitter) / 1000)


__all__ = ["run_cas", "MAX_ATTEMPTS", "CasHint"]
