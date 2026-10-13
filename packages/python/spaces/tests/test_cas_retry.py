"""Tests for run_cas retry logic."""
import pytest
from starfish_sdk.types import ConflictError
from starfish_spaces.cas_retry import CasHint, run_cas, MAX_ATTEMPTS


async def test_run_cas_succeeds_first_try():
    calls = []

    async def fn():
        calls.append(1)

    await run_cas(fn)
    assert len(calls) == 1


async def test_run_cas_retries_on_conflict():
    calls = []

    async def fn():
        calls.append(1)
        if len(calls) < 2:
            raise ConflictError()

    await run_cas(fn)
    assert len(calls) == 2


async def test_run_cas_raises_after_max_attempts():
    calls = []

    async def fn():
        calls.append(1)
        raise ConflictError()

    async def no_sleep(_seconds):
        pass

    with pytest.raises(ConflictError):
        await run_cas(fn, sleep=no_sleep)

    assert len(calls) == MAX_ATTEMPTS


async def test_run_cas_backs_off_between_attempts():
    calls = []
    sleeps = []

    async def fn():
        calls.append(1)
        raise ConflictError()

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    with pytest.raises(ConflictError):
        await run_cas(fn, sleep=fake_sleep, rand=lambda: 0.0)

    # 5 attempts total, 4 backoffs between them.
    assert len(calls) == MAX_ATTEMPTS == 5
    # Jittered exponential (jitter=0 here): 80, 160, 320, 640 ms.
    assert sleeps == [0.08, 0.16, 0.32, 0.64]


async def test_run_cas_propagates_non_conflict_error():
    async def fn():
        raise ValueError("not a conflict")

    with pytest.raises(ValueError):
        await run_cas(fn)


async def test_run_cas_zero_arg_callback_unchanged():
    calls = []

    async def fn():
        calls.append(1)

    await run_cas(fn)
    assert len(calls) == 1


async def test_run_cas_passes_cas_hint_after_conflict():
    hints: list[CasHint] = []

    async def fn(hint: CasHint):
        hints.append(hint)
        if len(hints) < 2:
            raise ConflictError('{"error":"hash_mismatch","currentHash":"abc"}')

    async def no_sleep(_seconds):
        pass

    await run_cas(fn, sleep=no_sleep, rand=lambda: 0.0)

    assert len(hints) == 2
    assert hints[0] == CasHint(current_hash="", attempt=0)
    assert hints[1] == CasHint(current_hash="abc", attempt=1)
