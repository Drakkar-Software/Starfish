"""Generic SSE live-change transport for Starfish ``/events`` streams.

Mirrors the incremental frame-parsing logic from
``packages/ts/client/src/events.ts``.

Exports:
- :func:`parse_sse_frames` — WHATWG-compliant incremental SSE frame parser.
  Pure function, no I/O.
- :func:`subscribe_changes` — async generator that opens an auto-reconnecting
  SSE subscription with capped exponential backoff, yielding parsed event dicts.
"""

from __future__ import annotations

import asyncio
import json
from typing import AsyncGenerator, Callable, Optional


# ── parse_sse_frames ──────────────────────────────────────────────────────────

def parse_sse_frames(
    chunk: str,
    carry: str = "",
) -> tuple[list[dict], str]:
    """Incrementally parse SSE frames from a raw text chunk (WHATWG SSE spec §10.1).

    Call on each decoded chunk from the response body stream. Pass the ``carry``
    returned by the previous call as the next call's ``carry`` argument (start
    with ``""``). When the stream ends, any non-empty ``carry`` is an incomplete
    final frame and can be discarded.

    Only ``data:`` lines are extracted. ``id:``, ``event:``, ``retry:``, and
    comment (``:``) lines are intentionally skipped.  Multi-line ``data:``
    payloads within a single frame are joined with ``\\n`` per spec.

    Each completed frame whose data is valid JSON is returned as a parsed
    ``dict``. Frames whose data is not valid JSON are silently skipped.

    Args:
        chunk: Newly received text (already decoded from UTF-8).
        carry: Leftover incomplete-frame text from the previous call.

    Returns:
        ``(frames, new_carry)`` — ``frames`` is a list of parsed dicts from
        completed frames; ``new_carry`` is the leftover text for the next call.
    """
    # Normalise \\r\\n and \\r → \\n per spec.
    text = (carry + chunk).replace("\r\n", "\n").replace("\r", "\n")
    # Frames are separated by blank lines (two consecutive newlines).
    parts = text.split("\n\n")
    frames: list[dict] = []

    for part in parts[:-1]:
        data_lines: list[str] = []
        for line in part.split("\n"):
            if line.startswith("data:"):
                # WHATWG SSE §9.2.6: strip exactly ONE leading U+0020 SPACE after
                # the colon (a tab or a second space is part of the payload). Keeps
                # frame payloads byte-identical with the TypeScript parser.
                value = line[5:]
                data_lines.append(value[1:] if value.startswith(" ") else value)
            # id:, event:, retry:, and comment (:) lines are intentionally ignored.
        if data_lines:
            raw_data = "\n".join(data_lines)
            try:
                parsed = json.loads(raw_data)
                if isinstance(parsed, dict):
                    frames.append(parsed)
            except (json.JSONDecodeError, ValueError):
                pass

    # The last part may be an incomplete frame — carry it to the next call.
    return frames, parts[-1]


# ── subscribe_changes ─────────────────────────────────────────────────────────

async def subscribe_changes(
    *,
    url: "str | Callable[[], str]",
    headers: dict[str, str] | None = None,
    on_status: Optional[Callable[[int], None]] = None,
    initial_backoff_ms: int = 500,
    max_backoff_ms: int = 30_000,
    session=None,  # httpx.AsyncClient | None
) -> AsyncGenerator[dict, None]:
    """Subscribe to an SSE endpoint, yielding parsed event data as dicts.

    Opens an HTTP connection that expects ``text/event-stream`` and yields each
    fully-parsed SSE frame as a ``dict``.  Auto-reconnects with capped
    exponential backoff on disconnect or error.

    Args:
        url:               SSE endpoint URL, or a zero-argument factory that
                           returns a fresh URL on every reconnect attempt.
        headers:           Extra HTTP headers sent with every request.
        on_status:         Optional callback — called with the HTTP status code
                           on each successful connection attempt.
        initial_backoff_ms: First reconnect delay in milliseconds (default 500).
        max_backoff_ms:    Maximum reconnect delay cap (default 30 000).
        session:           Optional ``httpx.AsyncClient`` to reuse.  When
                           ``None`` a new client is created and closed on exit.

    Yields:
        Parsed event data dicts from ``data:`` lines of each SSE frame.

    The generator runs until it is closed by the caller (``aclose()`` or a
    ``break`` inside an ``async for`` loop). It never raises — network errors
    trigger a reconnect after the backoff delay.
    """
    import httpx  # local import so the module can be imported without httpx installed in tests that don't need it

    _headers: dict[str, str] = {"Accept": "text/event-stream", **(headers or {})}
    backoff = initial_backoff_ms / 1000.0  # work in seconds internally
    max_backoff = max_backoff_ms / 1000.0
    own_session = session is None
    client: httpx.AsyncClient = session if session is not None else httpx.AsyncClient()

    try:
        while True:
            resolved_url = url() if callable(url) else url
            try:
                async with client.stream("GET", resolved_url, headers=_headers) as resp:
                    if on_status is not None:
                        on_status(resp.status_code)

                    # On non-2xx, back off and retry.
                    if resp.status_code < 200 or resp.status_code >= 300:
                        await asyncio.sleep(backoff)
                        backoff = min(backoff * 2, max_backoff)
                        continue

                    # Successful connect — reset backoff.
                    backoff = initial_backoff_ms / 1000.0
                    carry = ""

                    async for chunk in resp.aiter_text():
                        frames, carry = parse_sse_frames(chunk, carry)
                        for frame in frames:
                            yield frame

            except (httpx.HTTPError, OSError):
                # Network error — fall through to backoff and retry.
                pass
            except GeneratorExit:
                return

            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)
    finally:
        if own_session:
            await client.aclose()
