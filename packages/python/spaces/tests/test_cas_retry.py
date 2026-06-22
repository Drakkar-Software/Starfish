"""Tests for run_cas retry logic."""
import pytest
from starfish_sdk.types import ConflictError
from starfish_spaces.cas_retry import run_cas, MAX_ATTEMPTS


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

    with pytest.raises(ConflictError):
        await run_cas(fn)

    assert len(calls) == MAX_ATTEMPTS


async def test_run_cas_propagates_non_conflict_error():
    async def fn():
        raise ValueError("not a conflict")

    with pytest.raises(ValueError):
        await run_cas(fn)
