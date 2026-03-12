"""Monotonically increasing timestamp generator."""


import time

_last = 0


def next_timestamp() -> int:
    """Return a monotonically increasing millisecond timestamp."""
    global _last
    now = int(time.time() * 1000)
    if now <= _last:
        _last += 1
    else:
        _last = now
    return _last
